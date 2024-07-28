from typing import Self

from binaryninja import BinaryView  # type:ignore
from binaryninja.log import Logger  # type:ignore
from binaryninja.plugin import BackgroundTaskThread  # type:ignore

from . import common, plugin

SUPPORTED_ARCHS = ["x86_64", "x86"]

logger = Logger(session_id=0, logger_name=plugin.NAME)


def deobfuscate_at_address(bv: BinaryView, address: int) -> None:
    DeobfuscateCodeAtAddressTask(bv=bv, address=address).start()


def deobfuscate_themida_spotter_tags(bv: BinaryView) -> None:
    DeobfuscateCodeAtThemidaSpotterTagsTask(bv=bv).start()


class DeobfuscateCodeAtAddressTask(BackgroundTaskThread):

    def __init__(self, bv: BinaryView, address: int):
        super().__init__(
            initial_progress_text=f"Deobfuscating code at 0x{address:x}",
            can_cancel=False,
        )
        self.bv = bv
        self.address = address

    def run(self: Self) -> None:
        if self.bv.arch is None:
            logger.log_error(
                "Could not get architecture of current binary view")
            return

        arch = str(self.bv.platform.arch)
        if arch not in SUPPORTED_ARCHS:
            logger.log_error(
                "Current binary view's architecture isn't supported by the plugin"
            )
            return

        progress_msg = f"Deobfuscating code at 0x{self.address:x}"
        logger.log_info(progress_msg)
        self.progress = f"({plugin.NAME}) {progress_msg}"

        # Deobfuscate the address pointed to by the user
        protected_func_addrs = [self.address]
        common.deobfuscate_addresses(self.bv, arch, protected_func_addrs)
        logger.log_info(f"Successfully simplified code at 0x{self.address:x}!")


class DeobfuscateCodeAtThemidaSpotterTagsTask(BackgroundTaskThread):

    THEMIDA_SPOTTER_TAG_TYPE = "Themida's obfuscated code entries"

    def __init__(self, bv: BinaryView):
        super().__init__(
            initial_progress_text=
            "Deobfuscating code marked by Themida Spotter",
            can_cancel=False,
        )
        self.bv = bv

    def run(self: Self) -> None:
        if self.bv.arch is None:
            logger.log_error(
                "Could not get architecture of current binary view")
            return

        arch = str(self.bv.platform.arch)
        if arch not in SUPPORTED_ARCHS:
            logger.log_error(
                "Current binary view's architecture isn't supported by the plugin"
            )
            return

        progress_msg = "Looking for Themida Spotter tags..."
        logger.log_info(progress_msg)
        self.progress = f"({plugin.NAME}) {progress_msg}"

        mutated_code_locations: list[int] = []
        # List Themida Spotter tags
        for addr, tag in self.bv.get_tags():
            # Look for Themida Spotter's mutated code entry tags
            if tag.type.name == self.THEMIDA_SPOTTER_TAG_TYPE and \
                "Mutated" in tag.data:
                mutated_code_locations.append(addr)

        # Deobfuscate all addresses marked by Themida Spotter
        logger.log_info(
            f"Found {len(mutated_code_locations)} mutated code entries")
        self.progress = f"({plugin.NAME}) Deobfuscating mutated functions"
        common.deobfuscate_addresses(self.bv, arch, mutated_code_locations)
        logger.log_info("Successfully simplified code!")
