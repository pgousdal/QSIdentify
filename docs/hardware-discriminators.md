# Hardware discriminators

`hardware_discriminators.json` stores candidate fields and their provenance.
Statuses are `candidate`, `observed-repeatable`, `externally-documented`,
`verified-discriminator`, and `rejected`. Only a verified discriminator may map
an observed value to hardware identity.

The initial offset 12–13 record is a candidate with unknown meaning and no
mapping. Candidate collisions and repeatability must be investigated across
independently ground-truthed devices before promotion. Byte position alone is
not a semantic interpretation.
