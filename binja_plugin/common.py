from binaryninja import BinaryView, BinaryReader, BinaryWriter  # type:ignore
from binaryninja.log import Logger  # type:ignore

from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from miasm.core.asmblock import AsmCFG
from miasm.core.locationdb import LocationDB
from themida_unmutate.miasm_utils import (MiasmContext, MiasmFunctionInterval,
                                          generate_code_redirect_patch,
                                          asm_resolve_final_in_place)
from themida_unmutate.unwrapping import unwrap_functions
from themida_unmutate.symbolic_execution import disassemble_and_simplify_functions

from . import plugin

logger = Logger(session_id=0, logger_name=plugin.NAME)


def get_binary_data(bv: BinaryView) -> bytearray:
    """
    Retrieve binary data from `bv` as single `bytearray`.
    Note: spaces between sections are replaced with 0s.
    """
    # Sort sections by start address
    sections = list(bv.sections.values())
    sorted_section = sorted(sections, key=lambda s: s.start)

    br = BinaryReader(bv)
    last_section_address = bv.original_base
    exe_data = bytearray()
    for section in sorted_section:
        # Pad with zeroes
        padding_size = section.start - last_section_address
        exe_data += b"\x00" * padding_size
        exe_data += br.read(section.length, section.start)
        last_section_address = section.start + section.length

    return exe_data


def create_miasm_context(arch: str, binary_base_address: int,
                         binary_data: bytearray) -> MiasmContext:
    """
    Create `MiasmContext` from a `bytearray`, given the architecture and base address.
    """
    loc_db = LocationDB()
    machine = Machine(arch)
    assert machine.dis_engine is not None
    container = Container.from_string(binary_data,
                                      loc_db,
                                      addr=binary_base_address)
    mdis = machine.dis_engine(container.bin_stream, loc_db=loc_db)
    lifter = machine.lifter(loc_db)

    return MiasmContext(loc_db, container, machine, mdis, lifter)


def deobfuscate_addresses(bv: BinaryView, arch: str,
                          mutated_code_addresses: list[int]) -> None:
    binary_data = get_binary_data(bv)
    miasm_ctx = create_miasm_context(arch, bv.original_base, binary_data)

    logger.log_info("Resolving mutated function(s)' address(es)...")
    mutated_func_addrs = unwrap_functions(miasm_ctx, mutated_code_addresses)

    # Disassemble mutated functions and simplify them
    logger.log_info("Deobfuscating mutated function(s)...")
    simplified_func_asmcfgs = disassemble_and_simplify_functions(
        miasm_ctx, mutated_func_addrs)

    # Map protected functions' addresses to their corresponding simplified `AsmCFG`
    func_addr_to_simplified_cfg = {
        mutated_code_addresses[i]: asm_cfg
        for i, asm_cfg in enumerate(simplified_func_asmcfgs)
    }

    # Rewrite the protected binary with the simplified function
    logger.log_info("Patching binary file...")
    rebuild_simplified_binary(miasm_ctx, func_addr_to_simplified_cfg, bv)

    # Relaunch analysis to take our changes into account
    bv.update_analysis()


def rebuild_simplified_binary(
    miasm_ctx: MiasmContext,
    func_addr_to_simplified_cfg: dict[int, tuple[int, AsmCFG,
                                                 MiasmFunctionInterval]],
    bv: BinaryView,
) -> None:
    """
    Regenerate simplified machine code and patch the binary in place via `bv`.
    """
    bw = BinaryWriter(bv)

    # Reassemble simplified AsmCFGs
    original_to_simplified: dict[int, int] = {}
    for protected_func_addr, val in func_addr_to_simplified_cfg.items():
        original_code_addr, simplified_asmcfg, orignal_asmcfg_interval = val

        # Generate the simplified machine code
        new_section_patches = asm_resolve_final_in_place(
            miasm_ctx.loc_db,
            miasm_ctx.mdis.arch,
            simplified_asmcfg,
            dst_interval=orignal_asmcfg_interval)

        # Apply patches
        for address, data in new_section_patches.items():
            bw.write(bytes(data), address)

        # Associate original addr to simplified addr
        original_to_simplified[protected_func_addr] = original_code_addr

    # Redirect functions to their simplified versions
    for target_addr in func_addr_to_simplified_cfg.keys():
        simplified_func_addr = original_to_simplified[target_addr]
        address, data = generate_code_redirect_patch(miasm_ctx, target_addr,
                                                     simplified_func_addr)
        bw.write(data, address)
