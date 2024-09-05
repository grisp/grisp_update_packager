# grisp_updater_packager

GRiSP Software Update Packager


## Build

    $ rebar3 copmile


## Usage

To create a software update package with system firmware and bootloader firmware
for a GRiSP 2 board with standard partition structure:

    grisp_update_packager:package(<<"package.tar">>, #{
        name := ReleaseName,
        version := ReleaseVersion,
        firmware => SystemFirmwarePath,
        bootloader => BootloaderFirmwarePath,
        mbr => [
            #{role => system, size => 268435456, start => 4194304},
            #{role => system, size => 268435456}
        ]
    }).

To generate a signed package, add the option `key_file` with the path to a PEM
encoded private key (not encrypted), or `key` with a decoded private key record.

Note that the firmwares must be raw uncompressed files.
