# Electronic identification

QSIdentify separates observed protocol facts from hardware hypotheses. A valid
firmware frame can confirm the Quansheng protocol and its reported firmware
string. It does not confirm the marketed model, MCU, PCB revision, flash size,
or bootloader revision.

The current `2.01.36` physical fixture therefore confirms only protocol and
firmware. Absence of an electronic discriminator is not evidence of a legacy
revision. Marketing names and production years are user evidence, not unique
electronic identifiers. Opening the radio remains the physical ground-truth
method while this project investigates whether reliable electronic evidence can
eventually make that unnecessary.

Confidence is scoped independently to transport, protocol, firmware, model
family, marketed model, hardware revision, MCU, PCB revision, bootloader, and
firmware compatibility. User labels are always marked `user-supplied`.

`qsidentify identify PORT --repeat 5` presents the identity, scoped evidence,
fingerprint, and still-unresolved properties. It transmits only the same
allowlisted identification read used by `probe`.
