# AWS MFA CLI

Simple CLI to manage AWS MFA profiles and obtain temporary session tokens.

First create static credentials and attach MFA device in AWS console.

## Install from releases

Download the latest release (that corresponds to your architecture) from the [Releases](https://github.com/verbalius/aws_mfa/releases) page and place the binary in your system PATH. Like this

```shell
mv aws_mfa /usr/local/bin/aws_mfa
aws_mfa --version
```

First use run create and follow instructions:

```shell
aws_mfa --create
```

To also have shell completion run this:

```shell
aws_mfa --install-completion
```

To authenticate and obtain temporary session tokens run:

| Pro tip you can press tab after typing `aws_mfa ` to see available profiles if shell completion is installed. |

```shell
aws_mfa my-profile
```

Also you can automatically fetch the profile name if you have already set the `AWS_PROFILE` environment variable:

```shell
export AWS_PROFILE=my-profile
aws_mfa
```

## Build

To build the tool, run:

```shell
go mod tidy
go build -o aws_mfa .
```

Then create a new MFA-enabled profile:

```shell
./aws_mfa --create
```

Finally authenticate and obtain temporary session tokens:

```shell
./aws_mfa my-profile
```

Install to the system PATH:

```
mv aws_mfa /usr/local/bin/
```
