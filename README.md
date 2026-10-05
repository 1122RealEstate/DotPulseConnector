# DotPulse Connector

The Hermes plugin that connects a Hermes to the DotPulse app. It presents the Pairing ID that the
user pastes, keeps the connection's credential on this machine, and holds the outbound connection
that lets the app reach this Hermes. It opens no port.

Version 0.4.1. Needs Hermes >=0.21.

## Install

```
DotPulse (iPhone)  ⇄ HTTPS/WSS ⇄  link.dotpulse.app  ⇄ HTTPS/WSS ⇄  this connector  ⇄  Hermes
```

It talks to DotPulse Link at `https://link.dotpulse.app` and to nothing else. That address is
written in the connector; it is never taken from a message.

## Install

Hermes installs a plugin with its own command and does not install one from a chat message. Once
per Hermes, with the commit that the official skill publishes for each version
(https://github.com/1122RealEstate/SkillDotPulse):

```bash
hermes plugins install 1122RealEstate/DotPulseConnector --ref <commit> --enable
hermes gateway restart
```

`--ref` pins the exact files: a commit names one set of them and no other.

Hermes scans the plugin before installing it and asks for confirmation.

## Check an installed copy

```bash
python3 ~/.hermes/plugins/dotpulse/verify.py
```

## Use

In DotPulse tap **Copiar conexión** and paste what it copies into your Hermes, or into your private
Telegram chat with it. `/dotpulse` lists what is connected; `/dotpulse desconectar <id>` revokes.

The skill that tells the agent how to use this plugin ships inside it (`skill/SKILL.md`).
