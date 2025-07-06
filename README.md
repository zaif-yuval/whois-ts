# whois-client

A production-ready TypeScript package for fetching and parsing WHOIS records for any domain, with robust TLD-specific parsing logic.

## Features

- Fetches WHOIS data using the [`whois`](https://www.npmjs.com/package/whois) npm package
- Parses WHOIS records into structured objects
- Handles hundreds of TLDs with custom regex logic
- Written in TypeScript, outputs types and declarations
- Fast, modern build system using [tsup](https://tsup.egoist.dev/)

## Project Inspiration & Dependencies

- **Depends on:** [`whois`](https://www.npmjs.com/package/whois) (npm package)
- **Parsing logic inspired by:** [python-whois](https://github.com/richardpenman/whois) ([License](https://github.com/richardpenman/whois/blob/master/LICENSE.txt))

## Installation

```sh
npm install @zaifyuval/whois-ts whois date-fns
```

## Usage

```ts
import {
  fetchAndParseWhois,
  WhoisRecord,
  WhoisDomainNotFoundError,
} from "@zaifyuval/whois-ts";

async function main() {
  try {
    const record: WhoisRecord = await fetchAndParseWhois("example.com");
    console.log(record);
  } catch (err) {
    if (err instanceof WhoisDomainNotFoundError) {
      console.error("Domain not found!");
    } else {
      console.error("Error:", err);
    }
  }
}

main();
```

## API

### `fetchAndParseWhois(domain: string): Promise<WhoisRecord>`

Fetches the WHOIS record for the given domain and parses it into a structured object.

### `WhoisRecord`

TypeScript interface describing all possible parsed fields (see `src/types.ts`).

### `WhoisDomainNotFoundError`

Custom error thrown if the domain is not found or has no WHOIS server.

## Development

- Source code in `src/`
- Build output in `dist/`
- Run `pnpm run build` to compile (uses `tsup`)
- Lint with `pnpm run lint`
- Format with `pnpm run format`

## Contributing

Contributions are welcome! Feel free to open issues or pull requests to add features, improve TLD support, or fix bugs.

## License

MIT
