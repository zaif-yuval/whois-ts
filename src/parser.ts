import { WhoisRecord, ParserOptions } from "./types";
import { WhoisDomainNotFoundError } from "./errors";
import { parse as dateParse, isValid as isDateValid } from "date-fns";

export class WhoisParser {
  private text: string;
  private options: ParserOptions;
  public data: WhoisRecord;

  constructor(text: string, options: ParserOptions) {
    this.text = text;
    this.options = options;

    // Run all "not found" checks for the selected configuration
    for (const check of this.options.notFoundChecks) {
      if (check(this.text)) {
        throw new WhoisDomainNotFoundError(
          "The WHOIS record indicates the domain was not found or is unavailable.",
        );
      }
    }

    this.data = this.initializeData();
    this.parse();
  }

  private initializeData(): WhoisRecord {
    // Start with an empty object. Properties will be added as they are found.
    return {};
  }

  private castDate(value: string): Date | undefined {
    const parsedDate = new Date(value);
    if (isDateValid(parsedDate)) {
      return parsedDate;
    }
    // Fallback for other potential formats
    const formatStrings = ["d-MMM-yyyy", "yyyy-MM-dd'T'HH:mm:ss'Z'"];
    for (const format of formatStrings) {
      const parsed = dateParse(value, format, new Date());
      if (isDateValid(parsed)) {
        return parsed;
      }
    }
    return undefined;
  }

  private preprocess(
    key: keyof WhoisRecord,
    value: string,
  ): string | Date | undefined {
    const trimmedValue = value.trim();
    if (String(key).toLowerCase().includes("date")) {
      return this.castDate(trimmedValue);
    }
    return trimmedValue;
  }

  private parse(): void {
    this.options.regexMap.forEach((regex, key) => {
      // Fields that can have multiple values are handled here
      if (regex.global) {
        const matches = this.text.matchAll(regex);
        const values = [...matches]
          .map((match) => this.preprocess(key, match[1] ?? match[0]) as string)
          .filter(Boolean);

        if (values.length > 0) {
          const uniqueValues = [...new Set(values)];
          // Use a type assertion to bypass the strict type checking for this dynamic assignment.
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          (this.data as any)[key] = uniqueValues;
        }
      } else {
        // Fields that can only have one value
        const match = this.text.match(regex);
        if (match && match[1]) {
          const value = this.preprocess(key, match[1]);
          if (value !== undefined) {
            // Use a type assertion to bypass the strict type checking for this dynamic assignment.
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            (this.data as any)[key] = value;
          }
        }
      }
    });
  }
}
