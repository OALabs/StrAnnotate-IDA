<p align="center">
    <img alt="Showcase" src="/assets/annotate.gif">
</p>

[![GitHub release](https://img.shields.io/github/v/release/oalabs/strannotate-ida.svg)](https://github.com/OALabs/hashdb-ida/releases) [![Chat](https://img.shields.io/badge/chat-Discord-blueviolet)](https://discord.gg/cw4U3WHvpn) [![Support](https://img.shields.io/badge/Support-Patreon-FF424D)](https://www.patreon.com/oalabs)

# StrAnnotate IDA Plugin
A simple way to annotate your IDB with externally decrypted strings tables. A few lines of python to make a tedious task into a click.

## Installing StrAnnotate 
Simply copy the latest release of strannotate.py into your IDA plugins directory and you are ready to start annotating!

## Strings Table JSON Format
The strings table must use the following specific JSON format.

```json
{
"strings":[
            { 
              "offset":<file offset>, 
              "value":<ascii string>
            }, ...
          ]
}
```

## UnpacMe Strings Tables
StrAnnotate can accept any generated strings table as long as it follows the defined JSON format, but [**UnpacMe**](https://www.unpac.me) config strings data is specifically designed to work with StrAnnotate. 

The plugin will work with both a strings table [QakBot](https://www.unpac.me/results/1509c04f-669d-4d09-ae7a-f2e51e2c58a6#/) and with inline strings [RaccoonStealer](https://www.unpac.me/results/fa816fcb-6d78-46c2-8027-3b09b0bc6bc2#/).
<p align="center">
    <img alt="Showcase" src="/assets/str_dl.gif">
</p>
Simply download the strings table from UnpacMe and use StrAnnotate to import the strings into your IDB!


## ❗Compatibility Issues
The HashDB plugin has been developed for use with the __IDA 7+__ and __Python 3__ it is not backwards compatible. 
