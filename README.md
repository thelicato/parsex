<h1 align="center">
	<img src="https://github.com/thelicato/parsecx/blob/main/logo.png?raw=true" width="400">
</h1>

<h4 align="center">Parse and extract key data across multiple security tools</h4>

<p align="center">
  <a href="#-features">Features</a> •
  <a href="#-usage">Usage</a> •
  <a href="#-installation">Installation</a> •
  <a href="#-license">License</a> •
</p>

---

`parsecx` is a powerful command-line tool designed to streamline the process of parsing and extracting data from various security tools' outputs. It simplifies the complex task of data analysis in cybersecurity by providing a unified solution for interpreting and organizing data from multiple sources.

With `parsecx`, you can efficiently process and extract essential information from different security tool outputs, enabling faster and more informed decision-making in your cybersecurity operations.

The goal is to obtain a tool that meets the requirements of the community, therefore suggestions and PRs are very welcome!

## ⚡ Features

- Unified parsing
- Streamlined workflow
- Sample Files

This is the current list of compatible tools:

- nmap

## 📚 Usage

```
parsecx -h
```

This will display the help for the tool

```
      ____  ____ ______________  ______  __
     / __ \/ __ \` ___/ ___/ _ \/ ___/ |/_/
    / /_/ / /_/ / /  (__  )  __/ /___>  <
   / .___/\__,_/_/  /____/\___/\___/_/|_|
  /_/

v0.1.0 - https://github.com/thelicato/parsecx

Parse and extract key data across multiple security tools

Usage:
  parsecx [flags]

Flags:
  -h, --help           help for parsecx
  -i, --input string   Input to parse
```

## 🚀 Installation

Run the following command to install the latest version:

```
go install github.com/thelicato/parsecx@latest
```

Or you can simply grab an executable from the [Releases](https://github.com/thelicato/parsecx/releases) page.

## 🪪 License

_parsecx_ is made with 🖤 and released under the [GPL3 LICENSE](https://github.com/thelicato/parsecx/blob/main/LICENSE).
