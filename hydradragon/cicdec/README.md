# cicdec
Extract files from installers made with Clickteam Install Creator.

### Usage

`cicdec [<options>...] <installer> [<output_directory>]`

If no output directory is specified, all files are extracted to a subdirectory named after the input file.

##### Options

| Switch       | Description                                                  |
| ------------ | ------------------------------------------------------------ |
| -v <version> | Extract as installer version <version>. Auto-detection might not always work correctly, so it is possible to explicitly set the installer version. Possible values are `20`, `24`, `30`, `35`, `40` |
| -db        | Dump blocks. Save additional installer data like registry changes, license files and the uninstaller. This is considered raw data and might not be readable or usable. |
| -dfb       | Dump file block. This is raw binary data containing all files in compressed form and only useful for debugging purposes. |
| -si          | Simulate extraction without writing files to disk. Useful for debugging. |



### Limitations

- Installers, which contain multiple product versions, are not supported
	- This includes official Clickteam products, such as the Install Creator and Patch Maker installers themselves
- Encrypted installers are not supported
- Installer versions below 2.0.0.20 are untested and might not be supported. Please open an issue if you encounter an installer, which fails to extract