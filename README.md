# Seam Webhook SDK

[![npm](https://img.shields.io/npm/v/@seamapi/webhook.svg)](https://www.npmjs.com/package/@seamapi/webhook)
[![GitHub Actions](https://github.com/seamapi/javascript-webhook/actions/workflows/check.yml/badge.svg)](https://github.com/seamapi/javascript-webhook/actions/workflows/check.yml)

Webhook SDK for the Seam API written in TypeScript.

## Description

[Seam] makes it easy to integrate IoT devices with your applications.
This is an official SDK for the Seam API.
Please refer to the official [Seam Docs] to get started.

The Seam API implements webhooks using [Svix].
This SDK exports a thin wrapper around the svix package
Use it to parse and validate Seam webhook events
with full TypeScript support for Seam event types.

Refer to the [Svix docs on Consuming Webhooks] for
an in-depth guide on best-practices for handling webhooks
in your application.

[Seam]: https://www.seam.co/
[Seam Docs]: https://docs.seam.co/latest/
[Svix]: https://www.svix.com/
[Svix docs on Consuming Webhooks]: https://docs.svix.com/receiving/introduction

## Installation

> [!IMPORTANT]
> This is a low-level package meant for applications and libraries with particular dependency requirements.
> Before using this package, ensure you understand the installation and updating instructions.
> This SDK is entirely contained in the [seam package].
> Seam recommends using that package instead for simpler dependency management.

Add this as a dependency to your project using [npm] with

```
$ npm install @seamapi/webhook
```

[npm]: https://www.npmjs.com/
[seam package]: https://www.npmjs.com/package/seam

### Optional Peer Dependencies for TypeScript

This package has optional peer dependencies for TypeScript users.
Recent versions of npm will automatically install peer dependencies by default.
For those users, no additional steps are necessary for full TypeScript support,
however users should still explicitly install the latest types (see the next section).

Other package managers require peer dependencies to be added manually.
Refer to any warnings generated by your package manager
about missing peer dependencies and install them as needed.
Refer to the next section for keeping the types updated.

#### Keeping up with the latest types

This package depends on [@seamapi/types] for the latest TypeScript types.
New versions of this SDK are generally not released when new types are published.
Unless your project frequently runs a blanket `npm update`,
the types will become outdated with the Seam API over time.
Thus, users of this package should explicitly install the types with

```
$ npm install -D @seamapi/types
```

and update them when consuming new API features with

```
$ npm install -D @seamapi/types@latest
```

## Usage

First, create a webhook using the Seam API or Seam Console
and obtain a Seam webhook secret.

> [!TIP]
> This example is for [Express], see the [Svix docs for more examples in specific frameworks](https://docs.svix.com/receiving/verifying-payloads/how).

```js
import { env } from 'node:process'

import { SeamWebhook } from '@seamapi/webhook'
import express from 'express'
import bodyParser from 'body-parser'

const app = express()

const webhook = new SeamWebhook(env.SEAM_WEBHOOK_SECRET)

app.post(
  '/webhook',
  bodyParser.raw({ type: 'application/json' }),
  (req, res) => {
    let data
    try {
      data = webhook.verify(req.body, req.headers)
    } catch {
      return res.status(400).send()
    }
    storeEvent(data, (err) => {
      if (err != null) {
        return res.status(500).send()
      }
      res.status(204).send()
    })
  },
)

const storeEvent = (data, callback) => {
  console.log(data)
  callback()
}

app.listen(8080, () => {
  console.log('Ready to receive webhooks at http://localhost:8080/webhook')
})
```

[Express]: https://expressjs.com/

## Development and Testing

### Quickstart

```
$ git clone https://github.com/seamapi/javascript-webhook.git
$ cd javascript-webhook
$ nvm install
$ npm install
$ npm run test:watch
```

Primary development tasks are defined under `scripts` in `package.json`
and available via `npm run`.
View them with

```
$ npm run
```

### Source code

The [source code] is hosted on GitHub.
Clone the project with

```
$ git clone git@github.com:seamapi/javascript-webhook.git
```

[source code]: https://github.com/seamapi/javascript-webhook

### Requirements

You will need [Node.js] with [npm] and a [Node.js debugging] client.

Be sure that all commands run under the correct Node version, e.g.,
if using [nvm], install the correct version with

```
$ nvm install
```

Set the active version for each shell session with

```
$ nvm use
```

Install the development dependencies with

```
$ npm install
```

[Node.js]: https://nodejs.org/
[Node.js debugging]: https://nodejs.org/en/docs/guides/debugging-getting-started/
[npm]: https://www.npmjs.com/
[nvm]: https://github.com/creationix/nvm

### Publishing

#### Automatic

New versions are released automatically with [semantic-release]
as long as commits follow the [Angular Commit Message Conventions].

[Angular Commit Message Conventions]: https://semantic-release.gitbook.io/semantic-release/#commit-message-format
[semantic-release]: https://semantic-release.gitbook.io/

#### Manual

Publish a new version by triggering a [version workflow_dispatch on GitHub Actions].
The `version` input will be passed as the first argument to [npm-version].

This may be done on the web or using the [GitHub CLI] with

```
$ gh workflow run version.yml --raw-field version=<version>
```

[GitHub CLI]: https://cli.github.com/
[npm-version]: https://docs.npmjs.com/cli/version
[version workflow_dispatch on GitHub Actions]: https://github.com/seamapi/javascript-webhook/actions?query=workflow%3Aversion

## GitHub Actions

_GitHub Actions should already be configured: this section is for reference only._

The following repository secrets must be set on [GitHub Actions]:

- `NPM_TOKEN`: npm token for installing and publishing packages.
- `GH_TOKEN`: A personal access token for the bot user with
  `packages:write` and `contents:write` permission.
- `GIT_USER_NAME`: The GitHub bot user's real name.
- `GIT_USER_EMAIL`: The GitHub bot user's email.
- `GPG_PRIVATE_KEY`: The GitHub bot user's [GPG private key].
- `GPG_PASSPHRASE`: The GitHub bot user's GPG passphrase.

[GitHub Actions]: https://github.com/features/actions
[GPG private key]: https://github.com/marketplace/actions/import-gpg#prerequisites

## Contributing

> If using squash merge, edit and ensure the commit message follows the [Angular Commit Message Conventions] specification.
> Otherwise, each individual commit must follow the [Angular Commit Message Conventions] specification.

1. Create your feature branch (`git checkout -b my-new-feature`).
2. Make changes.
3. Commit your changes (`git commit -am 'Add some feature'`).
4. Push to the branch (`git push origin my-new-feature`).
5. Create a new draft pull request.
6. Ensure all checks pass.
7. Mark your pull request ready for review.
8. Wait for the required approval from the code owners.
9. Merge when ready.

[Angular Commit Message Conventions]: https://semantic-release.gitbook.io/semantic-release/#commit-message-format

## License

This npm package is licensed under the MIT license.

## Warranty

This software is provided by the copyright holders and contributors "as is" and
any express or implied warranties, including, but not limited to, the implied
warranties of merchantability and fitness for a particular purpose are
disclaimed. In no event shall the copyright holder or contributors be liable for
any direct, indirect, incidental, special, exemplary, or consequential damages
(including, but not limited to, procurement of substitute goods or services;
loss of use, data, or profits; or business interruption) however caused and on
any theory of liability, whether in contract, strict liability, or tort
(including negligence or otherwise) arising in any way out of the use of this
software, even if advised of the possibility of such damage.
