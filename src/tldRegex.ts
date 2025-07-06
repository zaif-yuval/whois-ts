import { ParserOptions, WhoisRecord } from "./types";

/**
 * Base regular expressions for a generic WHOIS record.
 */
export const baseRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /Domain Name:\s*(.+)/i],
  ["registrar", /Registrar:\s*(.+)/i],
  ["registrarUrl", /Registrar URL:\s*(.+)/i],
  ["reseller", /Reseller:\s*(.+)/i],
  ["whoisServer", /Whois Server:\s*(.+)/i],
  ["referralUrl", /Referral URL:\s*(.+)/i],
  ["updatedDate", /Updated Date:\s*(.+)/i],
  ["creationDate", /Creation Date:\s*(.+)/i],
  ["expirationDate", /Expir\w+ Date:\s*(.+)/i],
  ["nameServers", /Name Server:\s*(.+)/gi],
  ["status", /Status:\s*(.+)/gi],
  [
    "emails",
    /[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?/gi,
  ],
  ["dnssec", /dnssec:\s*(\S+)/i],
  ["name", /Registrant Name:\s*(.+)/i],
  ["org", /Registrant\s*Organization:\s*(.+)/i],
  ["address", /Registrant Street:\s*(.+)/i],
  ["city", /Registrant City:\s*(.+)/i],
  ["state", /Registrant State\/Province:\s*(.+)/i],
  ["registrantPostalCode", /Registrant Postal Code:\s*(.+)/i],
  ["country", /Registrant Country:\s*(.+)/i],
]);

/**
 * Specific regex overrides for .org domains, based on the provided Python class.
 * It uses most base regexes but overrides expirationDate and removes registrant details
 * not included in the Python `WhoisOrg` regex dictionary.
 */
export const orgRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /Domain Name:\s*(.+)/i],
  ["registrar", /Registrar:\s*(.+)/i],
  ["whoisServer", /Whois Server:\s*(.+)/i],
  ["referralUrl", /Referral URL:\s*(.+)/i],
  ["updatedDate", /Updated Date:\s*(.+)/i],
  ["creationDate", /Creation Date:\s*(.+)/i],
  ["expirationDate", /Registry Expiry Date:\s*(.+)/i], // .org specific
  ["nameServers", /Name Server:\s*(.+)/gi],
  ["status", /Status:\s*(.+)/gi],
  [
    "emails",
    /[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?/gi,
  ],
]);

// Define parser options for different TLDs
export const defaultParserOptions: ParserOptions = {
  regexMap: baseRegexMap,
  notFoundChecks: [
    (text) =>
      text.includes("This TLD has no whois server") ||
      text.includes("No whois server is known for this kind of object"),
  ],
};

export const comParserOptions: ParserOptions = {
  regexMap: baseRegexMap,
  notFoundChecks: [
    ...defaultParserOptions.notFoundChecks,
    (text) => text.includes('No match for "'),
  ],
};

export const orgParserOptions: ParserOptions = {
  regexMap: orgRegexMap,
  notFoundChecks: [
    ...defaultParserOptions.notFoundChecks,
    (text) =>
      text.trim().toUpperCase().startsWith("NOT FOUND") ||
      text.trim().startsWith("Domain not found"),
  ],
};

/**
 * Specific regex map for .cl domains, adapted from the Python WhoisCl class.
 */
export const clRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /Domain name:\s*(.+)/i],
  ["name", /Registrant name:\s*(.+)/i],
  ["org", /Registrant organisation:\s*(.+)/i],
  ["registrar", /registrar name:\s*(.+)/i],
  ["registrarUrl", /Registrar URL:\s*(.+)/i],
  ["creationDate", /Creation date:\s*(.+)/i],
  ["expirationDate", /Expiration date:\s*(.+)/i],
  ["nameServers", /Name server:\s*(.+)/gi],
]);

export const clParserOptions: ParserOptions = {
  regexMap: clRegexMap,
  notFoundChecks: [
    (text) => text.includes('No match for "'),
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .sg domains, adapted from the Python WhoisSG class.
 */
export const sgRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /Domain name:\s*(.+)/i],
  ["status", /Domain Status:\s*(.+)/gi],
  ["name", /Registrant:\n\s+Name:(.+)/i],
  ["registrar", /Registrar:\s*(.+)/i],
  ["creationDate", /Creation date:\s*(.+)/i],
  ["updatedDate", /Updated Date:\s*(.+)/i],
  ["expirationDate", /Registry Expiry Date:\s*(.+)/i],
  ["dnssec", /DNSSEC:\s*(.+)/i],
  ["nameServers", /Name server:\s*(.+)/gi],
]);

export const sgParserOptions: ParserOptions = {
  regexMap: sgRegexMap,
  notFoundChecks: [
    (text) => text.includes("Domain Not Found"),
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .pe domains, adapted from the Python WhoisPe class.
 */
export const peRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /Domain name:\s*(.+)/i],
  ["status", /Domain Status:\s*(.+)/gi],
  ["whoisServer", /WHOIS Server:\s*(.+)/i],
  ["name", /Registrant name:\s*(.+)/i],
  ["registrar", /Sponsoring Registrar:\s*(.+)/i],
  ["org", /Admin Name:\s*(.+)/i],
  ["emails", /Admin Email:\s*(.+)/i],
  ["dnssec", /DNSSEC:\s*(.+)/i],
  ["nameServers", /Name server:\s*(.+)/gi],
]);

export const peParserOptions: ParserOptions = {
  regexMap: peRegexMap,
  notFoundChecks: [
    (text) => text.includes('No match for "'),
    ...defaultParserOptions.notFoundChecks,
  ],
};

// .space, .com, .net use the defaultParserOptions or comParserOptions as appropriate.
// If you want to add explicit options for .space and .net:
export const spaceParserOptions: ParserOptions = {
  regexMap: baseRegexMap,
  notFoundChecks: [
    (text) => text.includes('No match for "'),
    ...defaultParserOptions.notFoundChecks,
  ],
};

export const netParserOptions: ParserOptions = {
  regexMap: baseRegexMap,
  notFoundChecks: [
    (text) => text.includes('No match for "'),
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .ro domains, adapted from the Python WhoisRo class.
 */
export const roRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /Domain Name:\s*(.+)/i],
  ["status", /Domain Status:\s*(.+)/gi],
  ["registrar", /Registrar:\s*(.+)/i],
  ["referralUrl", /Referral URL:\s*(.+)/i],
  ["creationDate", /Registered On:\s*(.+)/i],
  ["expirationDate", /Expires On:\s*(.+)/i],
  ["nameServers", /Nameserver:\s*(.+)/gi],
  ["dnssec", /DNSSEC:\s*(.+)/i],
]);

export const roParserOptions: ParserOptions = {
  regexMap: roRegexMap,
  notFoundChecks: [
    (text) => text.trim() === "NOT FOUND",
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .ru domains, adapted from the Python WhoisRu class.
 */
export const ruRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /domain:\s*(.+)/i],
  ["registrar", /registrar:\s*(.+)/i],
  ["creationDate", /created:\s*(.+)/i],
  ["expirationDate", /paid-till:\s*(.+)/i],
  ["nameServers", /nserver:\s*(.+)/gi],
  ["status", /state:\s*(.+)/gi],
  [
    "emails",
    /[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?/gi,
  ],
  ["org", /org:\s*(.+)/i],
]);

export const ruParserOptions: ParserOptions = {
  regexMap: ruRegexMap,
  notFoundChecks: [
    (text) => text.includes("No entries found"),
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .nl domains, adapted from the Python WhoisNl class.
 */
export const nlRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /Domain Name:\s*(.+)/i],
  ["expirationDate", /Date\sout\sof\squarantine:\s*(.+)/i],
  ["updatedDate", /Updated\sDate:\s*(.+)/i],
  ["creationDate", /Creation\sDate:\s*(.+)/i],
  ["status", /Status:\s*(.+)/gi],
  ["registrar", /Registrar:\s*(.*\n)/i],
  ["dnssec", /DNSSEC:\s*(.+)/i],
  // Additional registrar fields could be mapped if needed
]);

export const nlParserOptions: ParserOptions = {
  regexMap: nlRegexMap,
  notFoundChecks: [
    (text) => text.endsWith("is free"),
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .lt domains, adapted from the Python WhoisLt class.
 */
export const ltRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /Domain:\s?(.+)/i],
  ["expirationDate", /Expires:\s?(.+)/i],
  ["creationDate", /Registered:\s?(.+)/i],
  ["status", /\nStatus:\s?(.+)/gi],
]);

export const ltParserOptions: ParserOptions = {
  regexMap: ltRegexMap,
  notFoundChecks: [
    (text) => text.endsWith("available"),
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .name domains.
 */
export const nameRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /Domain Name:\s*(.+)/i],
  ["registrar", /Sponsoring Registrar:\s*(.+)/i],
  ["creationDate", /Created On:\s*(.+)/i],
  ["expirationDate", /Expires On:\s*(.+)/i],
  ["updatedDate", /Updated On:\s*(.+)/i],
  ["nameServers", /Name Server:\s*(.+)/gi],
  ["status", /Domain Status:\s*(.+)/gi],
]);

export const nameParserOptions: ParserOptions = {
  regexMap: nameRegexMap,
  notFoundChecks: [
    (text) => text.includes("No match for "),
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .us domains.
 */
export const usRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /Domain Name:\s*(.+)/i],
  ["whoisServer", /Registrar WHOIS Server:\s*(.+)/i],
  ["registrar", /Registrar:\s*(.+)/i],
  ["registrarUrl", /Registrar URL:\s*(.+)/i],
  ["status", /Domain Status:\s*(.+)/gi],
  ["nameServers", /Name Server:\s*(.+)/gi],
  ["creationDate", /Creation Date:\s*(.+)/i],
  ["expirationDate", /Registry Expiry Date:\s*(.+)/i],
  ["updatedDate", /Updated Date:\s*(.+)/i],
  ["org", /Registrant Organization:\s*(.+)/i],
  ["name", /Registrant Name:\s*(.+)/i],
  ["address", /Registrant Street:\s*(.+)/i],
  ["city", /Registrant City:\s*(.+)/i],
  ["state", /Registrant State\/Province:\s*(.+)/i],
  ["registrantPostalCode", /Registrant Postal Code:\s*(.+)/i],
  ["country", /Registrant Country:\s*(.+)/i],
  ["emails", /Registrant Email:\s*(.+)/i],
]);

export const usParserOptions: ParserOptions = {
  regexMap: usRegexMap,
  notFoundChecks: [
    (text) => text.includes("No Data Found"),
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .pl domains.
 */
export const plRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /DOMAIN NAME:\s*(.+)\n/i],
  ["nameServers", /nameservers:\s+([^\s]+)\.[^\n]*\n/gi],
  ["registrar", /REGISTRAR:\s*(.+)/i],
  ["registrarUrl", /URL:\s*(.+)/i],
  ["status", /Registration status:\n\s*(.+)/i],
  ["name", /Registrant:\n\s*(.+)/i],
  ["creationDate", /(?<! )created:\s*(.+)\n/i],
  ["expirationDate", /renewal date:\s*(.+)/i],
  ["updatedDate", /last modified:\s*(.+)\n/i],
]);

export const plParserOptions: ParserOptions = {
  regexMap: plRegexMap,
  notFoundChecks: [
    (text) => text.includes("No information available about domain name"),
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .group domains.
 */
export const groupRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /Domain Name:\s*(.+)/i],
  ["whoisServer", /Registrar WHOIS Server:\s*(.+)/i],
  ["registrarUrl", /Registrar URL:\s*(.+)/i],
  ["updatedDate", /Updated Date:\s*(.+)/i],
  ["creationDate", /Creation Date:\s*(.+)/i],
  ["expirationDate", /Expir\w+ Date:\s*(.+)/i],
  ["registrar", /Registrar:\s*(.+)/i],
  ["status", /Domain status:\s*(.+)/gi],
  ["name", /Registrant Name:\s*(.+)/i],
  ["nameServers", /Name Server:\s*(.+)/gi],
]);

export const groupParserOptions: ParserOptions = {
  regexMap: groupRegexMap,
  notFoundChecks: [
    (text) => text.includes("Domain not found"),
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .ca domains.
 */
export const caRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /Domain name:\s*(.+)/i],
  ["whoisServer", /Registrar WHOIS Server:\s*(.+)/i],
  ["registrar", /Registrar:\s*(.+)/i],
  ["registrarUrl", /Registrar URL:\s*(.+)/i],
  ["name", /Registrant Name:\s*(.+)/i],
  ["status", /Domain status:\s*(.+)/gi],
  ["emails", /Email:\s*(.+)/gi],
  ["updatedDate", /Updated Date:\s*(.+)/i],
  ["creationDate", /Creation Date:\s*(.+)/i],
  ["expirationDate", /Expiry Date:\s*(.+)/i],
  ["dnssec", /dnssec:\s*([\S]+)/i],
  ["nameServers", /Name Server:\s*(.+)/gi],
]);

export const caParserOptions: ParserOptions = {
  regexMap: caRegexMap,
  notFoundChecks: [
    (text) =>
      text.includes("Domain status:         available") ||
      text.includes("Not found:"),
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .me domains.
 */
export const meRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /Domain Name:\s*(.+)/i],
  ["creationDate", /Creation Date:\s*(.+)/i],
  ["updatedDate", /Updated Date:\s*(.+)/i],
  ["expirationDate", /Registry Expiry Date:\s*(.+)/i],
  ["registrar", /Registrar:\s*(.+)/i],
  ["status", /Domain Status:\s*(.+)/gi],
  ["name", /Registrant Name:\s*(.+)/i],
  ["org", /Registrant Organization:\s*(.+)/i],
  ["address", /Registrant Address:\s*(.+)/i],
  ["city", /Registrant City:\s*(.+)/i],
  ["state", /Registrant State\/Province:\s*(.+)/i],
  ["country", /Registrant Country\/Economy:\s*(.+)/i],
  ["registrantPostalCode", /Registrant Postal Code:\s*(.+)/i],
  ["emails", /Registrant E-mail:\s*(.+)/i],
  ["nameServers", /Nameservers:\s*(.+)/gi],
]);

export const meParserOptions: ParserOptions = {
  regexMap: meRegexMap,
  notFoundChecks: [
    (text) => text.includes("NOT FOUND"),
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .uk domains.
 */
export const ukRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /Domain name:\s*(.+)/i],
  ["registrar", /Registrar:\s*(.+)/i],
  ["registrarUrl", /URL:\s*(.+)/i],
  ["status", /Registration status:\s*(.+)/gi],
  ["name", /Registrant:\s*(.+)/i],
  ["creationDate", /Registered on:\s*(.+)/i],
  ["expirationDate", /Expiry date:\s*(.+)/i],
  ["updatedDate", /Last updated:\s*(.+)/i],
  [
    "nameServers",
    /([\w.-]+\.(?:[\w-]+\.){1,2}[a-zA-Z]{2,}(?!\s+Relevant|\s+Data))\s+/gi,
  ],
]);

export const ukParserOptions: ParserOptions = {
  regexMap: ukRegexMap,
  notFoundChecks: [
    (text) => text.includes("No match for "),
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .fr domains.
 */
export const frRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /domain:\s*(.+)/i],
  ["registrar", /registrar:\s*(.+)/i],
  ["creationDate", /created:\s*(.+)/i],
  ["expirationDate", /Expir\w+ Date:\s?(.+)/i],
  ["nameServers", /nserver:\s*(.+)/gi],
  ["status", /status:\s*(.+)/gi],
  [
    "emails",
    /[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?/gi,
  ],
  ["updatedDate", /last-update:\s*(.+)/i],
]);

export const frParserOptions: ParserOptions = {
  regexMap: frRegexMap,
  notFoundChecks: [
    (text) => text.includes("No entries found"),
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .fi domains.
 */
export const fiRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /domain\.?:\s*([\S]+)/i],
  ["name", /Holder\s*name\.?:\s*(.+)/i],
  ["address", /Holder[\w\W]*address\.?:\s*(.+)/i],
  // phone and email are not in WhoisRecord, so omitted
  ["status", /status\.?:\s*(.+)/gi],
  ["creationDate", /created\.?:\s*([\S]+)/i],
  ["updatedDate", /modified\.?:\s*([\S]+)/i],
  ["expirationDate", /expires\.?:\s*([\S]+)/i],
  ["nameServers", /nserver\.?:\s*([\S]+) \[\S+\]/gi],
  ["dnssec", /dnssec\.?:\s*([\S]+)/i],
  ["registrar", /Registrar\s*registrar\.?:\s*(.+)/i],
  // registrar_site is not in WhoisRecord, so omitted
]);

export const fiParserOptions: ParserOptions = {
  regexMap: fiRegexMap,
  notFoundChecks: [
    (text) => text.includes("Domain not "),
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .jp domains.
 */
export const jpRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /^\[Domain Name\]\s*(.+)$/im],
  ["org", /^\[(?:Organization|Registrant)\](.+)$/im],
  ["creationDate", /\[Created on\]\s*(.+)/i],
  ["expirationDate", /\[Expires on\]\s*(.+)/i],
  ["nameServers", /^\[Name Server\]\s*(.+)$/gim],
  ["updatedDate", /^\[Last Updated?\]\s?(.+)$/im],
  ["status", /\[(?:State|Status)\]\s*(.+)/gi],
]);

export const jpParserOptions: ParserOptions = {
  regexMap: jpRegexMap,
  notFoundChecks: [
    (text) => text.includes("No match!!"),
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .au domains.
 */
export const auRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /Domain Name:\s*(.+)\n/i],
  ["updatedDate", /Last Modified:\s*(.+)\n/i],
  ["registrar", /Registrar Name:\s*(.+)\n/i],
  ["status", /Status:\s*(.+)/gi],
  ["name", /Registrant:\s*(.+)/i],
  ["nameServers", /Name Server:\s*(.+)/gi],
  // registrant_id, eligibility_type, registrant_contact_name are not in WhoisRecord, so omitted
]);

export const auParserOptions: ParserOptions = {
  regexMap: auRegexMap,
  notFoundChecks: [
    (text) => text.trim() === "No Data Found",
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .rs domains.
 */
export const rsRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /Domain name:\s*(.+)/i],
  ["status", /Domain status:\s*(.+)/gi],
  ["creationDate", /Registration date:\s*(.+)/i],
  ["updatedDate", /Modification date:\s*(.+)/i],
  ["expirationDate", /Expiration date:\s*(.+)/i],
  ["registrar", /Registrar:\s*(.+)/i],
  ["name", /Registrant:\s*(.+)/i],
  ["address", /Registrant:.*\nAddress:\s*(.+)/i],
  ["nameServers", /DNS:\s*(\S+)/gi],
  ["dnssec", /DNSSEC signed:\s*(\S+)/i],
]);

export const rsParserOptions: ParserOptions = {
  regexMap: rsRegexMap,
  notFoundChecks: [
    (text) => text.trim() === "%ERROR:103: Domain is not registered",
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .eu domains.
 */
export const euRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /Domain:\s*([^\n\r]+)/i],
  ["registrar", /Registrar:\n\s*Name:\s*([^\n\r]+)/i],
  ["registrarUrl", /\n\s*Website:\s*([^\n\r]+)/i],
  ["nameServers", /Name servers:\n\s*([\n\S\s]+)/i],
]);

export const euParserOptions: ParserOptions = {
  regexMap: euRegexMap,
  notFoundChecks: [
    (text) => text.trim() === "Status: AVAILABLE",
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .ee domains.
 */
export const eeRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /Domain:\s*[\n\r]+\s*name:\s*([^\n\r]+)/i],
  ["status", /Domain:\s*[\n\r]+\s*name:\s*[^\n\r]+\sstatus:\s*([^\n\r]+)/i],
  [
    "creationDate",
    /Domain:\s*[\n\r]+\s*name:\s*[^\n\r]+\sstatus:\s*[^\n\r]+\sregistered:\s*([^\n\r]+)/i,
  ],
  [
    "updatedDate",
    /Domain:\s*[\n\r]+\s*name:\s*[^\n\r]+\sstatus:\s*[^\n\r]+\sregistered:\s*[^\n\r]+\schanged:\s*([^\n\r]+)/i,
  ],
  [
    "expirationDate",
    /Domain:\s*[\n\r]+\s*name:\s*[^\n\r]+\sstatus:\s*[^\n\r]+\sregistered:\s*[^\n\r]+\schanged:\s*[^\n\r]+\sexpire:\s*([^\n\r]+)/i,
  ],
  ["registrar", /Registrar:\s*[\n\r]+\s*name:\s*([^\n\r]+)/i],
  ["nameServers", /nserver:\s*(.*)/gi],
]);

export const eeParserOptions: ParserOptions = {
  regexMap: eeRegexMap,
  notFoundChecks: [
    (text) => text.trim() === "Domain not found",
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .br domains.
 */
export const brRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /domain:\s*(.+)\n/i],
  ["name", /owner:\s*([\S ]+)/i],
  ["country", /country:\s*(.+)/i],
  ["creationDate", /created:\s*(.+)/i],
  ["updatedDate", /changed:\s*(.+)/i],
  ["expirationDate", /expires:\s*(.+)/i],
  ["status", /status:\s*(.+)/gi],
  ["nameServers", /nserver:\s*(.+)/gi],
  ["emails", /e-mail:\s*(.+)/gi],
]);

export const brParserOptions: ParserOptions = {
  regexMap: brRegexMap,
  notFoundChecks: [
    (text) => text.includes("Not found:"),
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .kr domains.
 */
export const krRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /Domain Name\s*:\s*(.+)/i],
  ["name", /Registrant\s*:\s*(.+)/i],
  ["address", /Registrant Address\s*:\s*(.+)/i],
  ["registrantPostalCode", /Registrant Zip Code\s*:\s*(.+)/i],
  ["creationDate", /Registered Date\s*:\s*(.+)/i],
  ["updatedDate", /Last updated Date\s*:\s*(.+)/i],
  ["expirationDate", /Expiration Date\s*:\s*(.+)/i],
  ["registrar", /Authorized Agency\s*:\s*(.+)/i],
  ["nameServers", /Host Name\s*:\s*(.+)/gi],
  ["emails", /AC E-Mail\s*:\s*(.+)/gi],
  ["status", /Domain Status\s*:\s*(.+)/gi],
]);

export const krParserOptions: ParserOptions = {
  regexMap: krRegexMap,
  notFoundChecks: [
    (text) => text.trim().endsWith(" no match"),
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .pt domains.
 */
export const ptRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /Domain:\s*(.+)/i],
  ["creationDate", /Creation Date:\s*(.+)/i],
  ["expirationDate", /Expiration Date:\s*(.+)/i],
  ["name", /Owner Name:\s*(.+)/i],
  ["address", /Owner Address:\s*(.+)/i],
  ["city", /Owner Locality:\s*(.+)/i],
  ["registrantPostalCode", /Owner ZipCode:\s*(.+)/i],
  ["emails", /Owner Email:\s*(.+)/i],
  ["status", /Domain Status:\s*(.+)/gi],
  ["nameServers", /Name Server:\s*(.+) \|/gi],
]);

export const ptParserOptions: ParserOptions = {
  regexMap: ptRegexMap,
  notFoundChecks: [
    (text) => text.trim() === "No entries found",
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .bg domains.
 */
export const bgRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /DOMAIN NAME:\s*(.+)\n/i],
  ["status", /registration status:\s*(.+)/i],
]);

export const bgParserOptions: ParserOptions = {
  regexMap: bgRegexMap,
  notFoundChecks: [
    (text) => text.includes("does not exist in database!"),
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .de domains.
 */
export const deRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /Domain:\s*(.+)/i],
  ["status", /Status:\s*(.+)/i],
  ["updatedDate", /Changed:\s*(.+)/i],
  ["name", /name:\s*(.+)/i],
  ["org", /Organisation:\s*(.+)/i],
  ["address", /Address:\s*(.+)/i],
  ["registrantPostalCode", /PostalCode:\s*(.+)/i],
  ["city", /City:\s*(.+)/i],
  ["country", /CountryCode:\s*(.+)/i],
  ["emails", /Email:\s*(.+)/gi],
  ["nameServers", /Nserver:\s*(.+)/gi],
  ["creationDate", /created:\s*(.+)/i],
]);

export const deParserOptions: ParserOptions = {
  regexMap: deRegexMap,
  notFoundChecks: [
    (text) => text.includes("Status: free"),
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .at domains.
 */
export const atRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /domain:\s*(.+)/i],
  ["registrar", /registrar:\s*(.+)/i],
  ["nameServers", /nserver:\s*(.+)/gi],
  ["name", /personname:\s*(.+)/i],
  ["org", /organization:\s*(.+)/i],
  ["address", /street address:\s*(.+)/i],
  ["registrantPostalCode", /postal code:\s*(.+)/i],
  ["city", /city:\s*(.+)/i],
  ["country", /country:\s*(.+)/i],
  ["updatedDate", /changed:\s*(.+)/i],
  ["emails", /e-mail:\s*(.+)/gi],
]);

export const atParserOptions: ParserOptions = {
  regexMap: atRegexMap,
  notFoundChecks: [
    (text) => text.includes("Status: free"),
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .be domains.
 */
export const beRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /Domain:\s*(.+)/i],
  ["status", /Status:\s*(.+)/i],
  ["name", /Name:\s*(.+)/i],
  ["org", /Organisation:\s*(.+)/i],
  ["emails", /Email:\s*(.+)/gi],
  ["creationDate", /Registered:\s*(.+)/i],
  ["nameServers", /Nameservers:\s*((?:\s+?[\w.]+\s)*)/i],
]);

export const beParserOptions: ParserOptions = {
  regexMap: beRegexMap,
  notFoundChecks: [
    (text) => text.includes("Status: AVAILABLE"),
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .info domains.
 */
export const infoRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /Domain Name:\s*(.+)/i],
  ["registrar", /Registrar:\s*(.+)/i],
  ["whoisServer", /Whois Server:\s*(.+)/i],
  ["referralUrl", /Referral URL:\s*(.+)/i],
  ["updatedDate", /Updated Date:\s*(.+)/i],
  ["creationDate", /Creation Date:\s*(.+)/i],
  ["expirationDate", /Registry Expiry Date:\s*(.+)/i],
  ["nameServers", /Name Server:\s*(.+)/gi],
  ["status", /Status:\s*(.+)/gi],
  [
    "emails",
    /[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?/gi,
  ],
  ["name", /Registrant Name:\s*(.+)/i],
  ["org", /Registrant Organization:\s*(.+)/i],
  ["address", /Registrant Street:\s*(.+)/i],
  ["city", /Registrant City:\s*(.+)/i],
  ["state", /Registrant State\/Province:\s*(.+)/i],
  ["registrantPostalCode", /Registrant Postal Code:\s*(.+)/i],
  ["country", /Registrant Country:\s*(.+)/i],
]);

export const infoParserOptions: ParserOptions = {
  regexMap: infoRegexMap,
  notFoundChecks: [
    (text) => text.includes("Domain not found"),
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .rf domains (alias for .ru).
 * This uses the same as .ru.
 */
export const rfParserOptions: ParserOptions = ruParserOptions;

/**
 * .su domains use the same parser as .ru
 */
export const suParserOptions: ParserOptions = ruParserOptions;

/**
 * .city domains use the same parser as .ru
 */
export const cityParserOptions: ParserOptions = ruParserOptions;

/**
 * .style domains use the same parser as .ru
 */
export const styleParserOptions: ParserOptions = ruParserOptions;

/**
 * .pyc (.рус) domains use the same parser as .ru
 */
export const pycParserOptions: ParserOptions = ruParserOptions;

/**
 * .bz and .studio domains use a custom parser similar to .ru but with more fields.
 * We'll map only those fields that exist in WhoisRecord.
 */
export const bzRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /Domain Name:\s*(.+)/i],
  ["whoisServer", /Registrar WHOIS Server:\s*(.+)/i],
  ["registrar", /Registrar:\s*(.+)/i],
  ["registrarUrl", /Registrar URL:\s*(.+)/i],
  ["status", /Domain Status:\s*(.+)/gi],
  ["name", /Registrant Name:\s*(.+)/i],
  ["org", /Registrant Organization:\s*(.+)/i],
  ["address", /Registrant Street:\s*(.+)/i],
  ["city", /Registrant City:\s*(.+)/i],
  ["state", /Registrant State\/Province:\s*(.+)/i],
  ["registrantPostalCode", /Registrant Postal Code:\s*(.+)/i],
  ["country", /Registrant Country:\s*(.+)/i],
  ["emails", /Registrant Email:\s*(.+)/i],
  ["creationDate", /Creation Date:\s*(.+)/i],
  ["expirationDate", /Registrar Registration Expiration Date:\s*(.+)/i],
  ["updatedDate", /Updated Date:\s*(.+)/i],
  ["dnssec", /DNSSEC:\s*(.+)/i],
  ["nameServers", /Name Server:\s*(.+)/gi],
]);

export const bzParserOptions: ParserOptions = {
  regexMap: bzRegexMap,
  notFoundChecks: [
    (text) => text.includes("No entries found"),
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * .studio domains use the same regex as .bz, but with a different not found check.
 */
export const studioParserOptions: ParserOptions = {
  regexMap: bzRegexMap,
  notFoundChecks: [
    (text) => text.includes("Domain not found."),
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .club domains.
 */
export const clubRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /Domain Name:\s*(.+)/i],
  ["registrar", /Sponsoring Registrar:\s*(.+)/i],
  ["registrarUrl", /Registrar URL \(registration services\):\s*(.+)/i],
  ["status", /Domain Status:\s*(.+)/gi],
  ["name", /Registrant Name:\s*(.+)/i],
  ["address", /Registrant Address1:\s*(.+)/i],
  ["city", /Registrant City:\s*(.+)/i],
  ["state", /Registrant State\/Province:\s*(.+)/i],
  ["registrantPostalCode", /Registrant Postal Code:\s*(.+)/i],
  ["country", /Registrant Country:\s*(.+)/i],
  ["emails", /Registrant Email:\s*(.+)/i],
  ["creationDate", /Domain Registration Date:\s*(.+)/i],
  ["expirationDate", /Domain Expiration Date:\s*(.+)/i],
  ["updatedDate", /Domain Last Updated Date:\s*(.+)/i],
  ["nameServers", /Name Server:\s*(.+)/gi],
]);

export const clubParserOptions: ParserOptions = {
  regexMap: clubRegexMap,
  notFoundChecks: [
    (text) => text.includes("Not found:"),
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .io domains.
 */
export const ioRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /Domain Name:\s*(.+)/i],
  ["registrar", /Registrar:\s*(.+)/i],
  ["registrarUrl", /Registrar URL:\s*(.+)/i],
  ["status", /Domain Status:\s*(.+)/gi],
  ["org", /Registrant Organization:\s*(.+)/i],
  ["state", /Registrant State\/Province:\s*(.+)/i],
  ["country", /Registrant Country:\s*(.+)/i],
  ["nameServers", /Name Server:\s*(.+)/gi],
  ["creationDate", /Creation Date:\s*(.+)/i],
  ["expirationDate", /Registry Expiry Date:\s*(.+)/i],
  ["updatedDate", /Updated Date:\s*(.+)/i],
]);

export const ioParserOptions: ParserOptions = {
  regexMap: ioRegexMap,
  notFoundChecks: [
    (text) => text.includes("is available for purchase"),
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .biz domains.
 */
export const bizRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /Domain Name:\s*(.+)/i],
  ["registrar", /Registrar:\s*(.+)/i],
  ["registrarUrl", /Registrar URL:\s*(.+)/i],
  ["status", /Domain Status:\s*(.+)/gi],
  ["name", /Registrant Name:\s*(.+)/i],
  ["address", /Registrant Street:\s*(.+)/i],
  ["city", /Registrant City:\s*(.+)/i],
  ["state", /Registrant State\/Province:\s*(.+)/i],
  ["registrantPostalCode", /Registrant Postal Code:\s*(.+)/i],
  ["country", /Registrant Country:\s*(.+)/i],
  ["emails", /Registrant Email:\s*(.+)/i],
  ["creationDate", /Creation Date:\s*(.+)/i],
  ["expirationDate", /Registrar Registration Expiration Date:\s*(.+)/i],
  ["updatedDate", /Updated Date:\s*(.+)/i],
  ["nameServers", /Name Server:\s*(.+)/gi],
]);

export const bizParserOptions: ParserOptions = {
  regexMap: bizRegexMap,
  notFoundChecks: [
    (text) => text.includes("No Data Found"),
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .mobi domains.
 */
export const mobiRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /Domain Name:\s*(.+)/i],
  ["registrar", /Registrar:\s*(.+)/i],
  ["status", /Domain Status:\s*(.+)/gi],
  ["name", /Registrant Name:\s*(.+)/i],
  ["org", /Registrant Organization:\s*(.+)/i],
  ["address", /Registrant Address:\s*(.+)/i],
  ["city", /Registrant City:\s*(.+)/i],
  ["state", /Registrant State\/Province:\s*(.+)/i],
  ["country", /Registrant Country\/Economy:\s*(.+)/i],
  ["registrantPostalCode", /Registrant Postal Code:\s*(.+)/i],
  ["emails", /Registrant E-mail:\s*(.+)/i],
  ["creationDate", /Creation Date:\s*(.+)/i],
  ["expirationDate", /Registry Expiry Date:\s*(.+)/i],
  ["updatedDate", /Updated Date:\s*(.+)/i],
  ["nameServers", /Name Server:\s*(.+)/gi],
]);

export const mobiParserOptions: ParserOptions = {
  regexMap: mobiRegexMap,
  notFoundChecks: [
    (text) => text.includes("NOT FOUND"),
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .kg domains.
 */
export const kgRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /Domain\s*([\w]+\.[\w]{2,5})/i],
  ["registrar", /Domain support:\s*(.+)/i],
  ["name", /Name:\s*(.+)/i],
  ["address", /Address:\s*(.+)/i],
  ["emails", /Email:\s*(.+)/i],
  ["creationDate", /Record created:\s*(.+)/i],
  ["expirationDate", /Record expires on\s*(.+)/i],
  ["updatedDate", /Record last updated on\s*(.+)/i],
  ["nameServers", /Name servers in the listed order:\s*([\d\w.\s]+)/i],
]);

export const kgParserOptions: ParserOptions = {
  regexMap: kgRegexMap,
  notFoundChecks: [
    (text) =>
      text.includes(
        "Data not found. This domain is available for registration",
      ),
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .ch and .li domains.
 */
export const chliRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /\nDomain name:\n*(.+)/i],
  ["name", /Holder of domain name:\s*(?:.*\n){1}\s*(.+)/i],
  ["address", /Holder of domain name:\s*(?:.*\n){2}\s*(.+)/i],
  ["registrar", /Registrar:\n*(.+)/i],
  ["creationDate", /First registration date:\n*(.+)/i],
  ["dnssec", /DNSSEC:([\S]+)/i],
  ["nameServers", /Name servers:\n *([\n\S\s]+)/i],
]);

export const chliParserOptions: ParserOptions = {
  regexMap: chliRegexMap,
  notFoundChecks: [
    (text) =>
      text.includes(
        "We do not have an entry in our database matching your query.",
      ),
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .id domains.
 */
export const idRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /Domain Name:(.+)/i],
  ["registrar", /Sponsoring Registrar Organization:(.+)/i],
  ["creationDate", /Created On:(.+)/i],
  ["expirationDate", /Expiration Date:(.+)/i],
  ["updatedDate", /Last Updated On:(.+)/i],
  ["dnssec", /DNSSEC:(.+)/i],
  ["status", /Status:(.+)/gi],
  ["nameServers", /Name Server:(.+)/gi],
  // Only fields that exist in WhoisRecord are mapped.
]);

export const idParserOptions: ParserOptions = {
  regexMap: idRegexMap,
  notFoundChecks: [
    (text) => text.includes("NOT FOUND"),
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .se domains.
 */
export const seRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /domain\.*: *(.+)/i],
  ["name", /holder\.*: *(.+)/i],
  ["creationDate", /created\.*: *(.+)/i],
  ["updatedDate", /modified\.*: *(.+)/i],
  ["expirationDate", /expires\.*: *(.+)/i],
  ["nameServers", /nserver\.*: *(.+)/gi],
  ["dnssec", /dnssec\.*: *(.+)/i],
  ["status", /status\.*: *(.+)/gi],
  ["registrar", /registrar: *(.+)/i],
]);

export const seParserOptions: ParserOptions = {
  regexMap: seRegexMap,
  notFoundChecks: [
    (text) => text.includes("not found."),
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .jobs domains.
 */
export const jobsRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /Domain Name: *(.+)/i],
  ["whoisServer", /Registrar WHOIS Server: *(.+)/i],
  ["registrarUrl", /Registrar URL: *(.+)/i],
  ["registrar", /Registrar: *(.+)/i],
  ["emails", /Registrar Abuse Contact Email: *(.+)/i],
  ["status", /Domain Status: *(.+)/gi],
  ["name", /Registrant Name: (.+)/i],
  ["org", /Registrant Organization: (.+)/i],
  ["address", /Registrant Street: (.*)/i],
  ["city", /Registrant City: (.*)/i],
  ["state", /Registrant State\/Province: (.*)/i],
  ["registrantPostalCode", /Registrant Postal Code: (.*)/i],
  ["country", /Registrant Country: (.+)/i],
  ["emails", /Registrant Email: (.+)/i],
  ["creationDate", /Creation Date: *(.+)/i],
  ["expirationDate", /Registry Expiry Date: *(.+)/i],
  ["updatedDate", /Updated Date: *(.+)/i],
  ["nameServers", /Name Server: *(.+)/gi],
]);

export const jobsParserOptions: ParserOptions = {
  regexMap: jobsRegexMap,
  notFoundChecks: [
    (text) => text.includes("not found."),
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .it domains.
 */
export const itRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /Domain: *(.+)/i],
  ["creationDate", /(?<! )Created: *(.+)/i],
  ["updatedDate", /(?<! )Last Update: *(.+)/i],
  ["expirationDate", /(?<! )Expire Date: *(.+)/i],
  ["status", /Status: *(.+)/gi],
  ["nameServers", /Nameservers[\s]((?:.+\n)*)/i],
  ["org", /(?<=Registrant)[\s\S]*?Organization:(.*)/i],
  ["address", /(?<=Registrant)[\s\S]*?Address:(.*)/i],
]);

export const itParserOptions: ParserOptions = {
  regexMap: itRegexMap,
  notFoundChecks: [
    (text) => text.includes("not found."),
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .sa domains.
 */
export const saRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /Domain Name: *(.+)/i],
  ["creationDate", /Created on: *(.+)/i],
  ["updatedDate", /Last Updated on: *(.+)/i],
  ["nameServers", /Name Servers:[\s]((?:.+\n)*)/i],
  ["name", /Registrant:\s*(.+)/i],
  ["address", /(?<=Registrant)[\s\S]*?Address:((?:.+\n)*)/i],
]);

export const saParserOptions: ParserOptions = {
  regexMap: saRegexMap,
  notFoundChecks: [
    (text) => text.includes("not found."),
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .sk domains.
 */
export const skRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /Domain: *(.+)/i],
  ["creationDate", /(?<=Domain:)[\s\w\W]*?Created: *(.+)/i],
  ["updatedDate", /(?<=Domain:)[\s\w\W]*?Updated: *(.+)/i],
  ["expirationDate", /Valid Until: *(.+)/i],
  ["nameServers", /Nameserver: *(.+)/gi],
  ["registrar", /(?<=Registrar)[\s\S]*?Organization:(.*)/i],
]);

export const skParserOptions: ParserOptions = {
  regexMap: skRegexMap,
  notFoundChecks: [
    (text) => text.includes("not found."),
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .mx domains.
 */
export const mxRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /Domain Name: *(.+)/i],
  ["creationDate", /Created On: *(.+)/i],
  ["updatedDate", /Last Updated On: *(.+)/i],
  ["expirationDate", /Expiration Date: *(.+)/i],
  ["nameServers", /DNS: (.*)/gi],
  ["registrar", /Registrar:\s*(.+)/i],
  ["name", /(?<=Registrant)[\s\S]*?Name:(.*)/i],
  ["city", /(?<=Registrant)[\s\S]*?City:(.*)/i],
  ["state", /(?<=Registrant)[\s\S]*?State:(.*)/i],
  ["country", /(?<=Registrant)[\s\S]*?Country:(.*)/i],
]);

export const mxParserOptions: ParserOptions = {
  regexMap: mxRegexMap,
  notFoundChecks: [
    (text) => text.includes("not found."),
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .tw domains.
 */
export const twRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /Domain Name: *(.+)/i],
  ["creationDate", /Record created on (.+) /i],
  ["expirationDate", /Record expires on (.+) /i],
  ["nameServers", /Domain servers in listed order:((?:\s.+)*)/i],
  ["registrar", /Registration Service Provider: *(.+)/i],
  ["registrarUrl", /Registration Service URL: *(.+)/i],
  ["name", /(?<=Registrant:)\s+(.*)/i],
  ["org", /(?<=Registrant:)\s*(.*)/i],
  ["city", /(?<=Registrant:)\s*(?:.*\n){5}\s+(.*),/i],
  ["address", /(?<=Registrant:)\s*(?:.*\n){4}\s+(.*)/i],
  ["state", /(?<=Registrant:)\s*(?:.*\n){5}.*, (.*)/i],
  ["country", /(?<=Registrant:)\s*(?:.*\n){6}\s+(.*)/i],
  // emails, phone, fax, admin, tech, billing not mapped (not in WhoisRecord)
]);

export const twParserOptions: ParserOptions = {
  regexMap: twRegexMap,
  notFoundChecks: [
    (text) => text.includes("not found."),
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .tr domains.
 */
export const trRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /\[\*\*\] Domain Name: *(.+)/i],
  ["creationDate", /Created on.*: *(.+)/i],
  ["expirationDate", /Expires on.*: *(.+)/i],
  ["status", /Transfer Status: *(.+)/i],
  ["nameServers", /\[\*\*\] Domain servers:((?:\s.+)*)/i],
  ["name", /(?<=\[\*\*\] Registrant:)[\s\S]((?:\s.+)*)/i],
  // admin, tech, billing, org, address, etc. not mapped (not in WhoisRecord)
]);

export const trParserOptions: ParserOptions = {
  regexMap: trRegexMap,
  notFoundChecks: [
    (text) => text.includes("not found."),
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .is domains.
 */
export const isRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /domain\.*: *(.+)/i],
  ["name", /person\.*: *(.+)/i],
  ["address", /address\.*: *(.+)/i],
  ["creationDate", /created\.*: *(.+)/i],
  ["expirationDate", /expires\.*: *(.+)/i],
  ["emails", /e-mail: *(.+)/i],
  ["nameServers", /nserver\.*: *(.+)/gi],
  ["dnssec", /dnssec\.*: *(.+)/i],
  // registrant_name not mapped (not in WhoisRecord)
]);

export const isParserOptions: ParserOptions = {
  regexMap: isRegexMap,
  notFoundChecks: [
    (text) => text.includes("No entries found"),
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .dk domains.
 */
export const dkRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /Domain: *(.+)/i],
  ["creationDate", /Registered: *(.+)/i],
  ["expirationDate", /Expires: *(.+)/i],
  ["registrar", /Registrar: *(.+)/i],
  ["dnssec", /Dnssec: *(.+)/i],
  ["status", /Status: *(.+)/i],
  ["nameServers", /Nameservers\n *([\n\S\s]+)/i],
  // registrant fields not mapped (not in WhoisRecord)
]);

export const dkParserOptions: ParserOptions = {
  regexMap: dkRegexMap,
  notFoundChecks: [
    (text) => text.includes("No match for "),
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .ai domains.
 */
export const aiRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /Domain Name\s*:\s*(.+)/i],
  ["status", /Domain Status:\s*(.+)/i],
  ["creationDate", /Creation Date:\s*(.+)/i],
  ["expirationDate", /Registry Expiry Date: *(.+)/i],
  ["registrar", /Registrar:\s*(.+)/i],
  ["name", /Registrant\s*Name:\s*(.+)/i],
  ["org", /Registrant\s*Organization:\s*(.+)/i],
  ["address", /Registrant\s*Street:\s*(.+)/i],
  ["city", /Registrant\s*City:\s*(.+)/i],
  ["state", /Registrant\s*State.*:\s*(.+)/i],
  ["registrantPostalCode", /Registrant\s*Postal\s*Code\s*:\s*(.+)/i],
  ["country", /Registrant\s*Country\s*:\s*(.+)/i],
  ["emails", /Registrant\s*Email\.*:\s*(.+)/i],
  ["nameServers", /Name Server\.*:\s*(.+)/gi],
]);

export const aiParserOptions: ParserOptions = {
  regexMap: aiRegexMap,
  notFoundChecks: [
    (text) => text.includes("not registered"),
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .il domains.
 */
export const ilRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /domain: *(.+)/i],
  ["expirationDate", /validity: *(.+)/i],
  ["name", /person: *(.+)/i],
  ["address", /address *(.+)/i],
  ["dnssec", /DNSSEC: *(.+)/i],
  ["status", /status: *(.+)/i],
  ["nameServers", /nserver: *(.+)/gi],
  ["emails", /e-mail: *(.+)/i],
  ["registrar", /registrar name: *(.+)/i],
  ["referralUrl", /registrar info: *(.+)/i],
  // phone not mapped (not in WhoisRecord)
]);

export const ilParserOptions: ParserOptions = {
  regexMap: ilRegexMap,
  notFoundChecks: [
    (text) => text.includes("No data was found"),
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .in domains.
 */
export const inRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /Domain Name:\s*(.+)/i],
  ["registrar", /Registrar:\s*(.+)/i],
  ["registrarUrl", /Registrar URL:\s*(.+)/i],
  ["updatedDate", /Updated Date:\s*(.+)|Last Updated On:\s*(.+)/i],
  ["creationDate", /Creation Date:\s*(.+)|Created On:\s*(.+)/i],
  ["expirationDate", /Expiration Date:\s*(.+)|Registry Expiry Date:\s*(.+)/i],
  ["nameServers", /Name Server:\s*(.+)/gi],
  ["org", /Registrant Organization:\s*(.+)/i],
  ["state", /Registrant State\/Province:\s*(.+)/i],
  ["status", /Status:\s*(.+)/gi],
  [
    "emails",
    /[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?/gi,
  ],
  ["country", /Registrant Country:\s*(.+)/i],
  ["dnssec", /DNSSEC:\s*([\S]+)/i],
]);

export const inParserOptions: ParserOptions = {
  regexMap: inRegexMap,
  notFoundChecks: [
    (text) => text.includes("NOT FOUND"),
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .cat domains.
 */
export const catRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /Domain Name:\s*(.+)/i],
  ["registrar", /Registrar:\s*(.+)/i],
  ["updatedDate", /Updated Date:\s*(.+)/i],
  ["creationDate", /Creation Date:\s*(.+)/i],
  ["expirationDate", /Registry Expiry Date:\s*(.+)/i],
  ["nameServers", /Name Server:\s*(.+)/gi],
  ["status", /Domain status:\s*(.+)/gi],
  [
    "emails",
    /[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?/gi,
  ],
]);

export const catParserOptions: ParserOptions = {
  regexMap: catRegexMap,
  notFoundChecks: [
    (text) => text.includes("no matching objects"),
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .ie domains.
 */
export const ieRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /Domain Name:\s*(.+)/i],
  ["creationDate", /Creation Date:\s*(.+)/i],
  ["expirationDate", /Registry Expiry Date:\s*(.+)/i],
  ["nameServers", /Name Server:\s*(.+)/gi],
  ["status", /Domain status:\s*(.+)/gi],
  ["registrar", /Registrar:\s*(.+)/i],
  [
    "emails",
    /[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?/gi,
  ],
]);

export const ieParserOptions: ParserOptions = {
  regexMap: ieRegexMap,
  notFoundChecks: [
    (text) => text.includes("no matching objects"),
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .nz domains.
 */
export const nzRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /domain_name:\s*([^\n\r]+)/i],
  ["registrar", /registrar_name:\s*([^\n\r]+)/i],
  ["updatedDate", /domain_datelastmodified:\s*([^\n\r]+)/i],
  ["creationDate", /domain_dateregistered:\s*([^\n\r]+)/i],
  ["expirationDate", /domain_datebilleduntil:\s*([^\n\r]+)/i],
  ["nameServers", /ns_name_\d*:\s*([^\n\r]+)/gi],
  ["status", /status:\s*([^\n\r]+)/gi],
  [
    "emails",
    /[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?/gi,
  ],
  ["name", /registrant_contact_name:\s*([^\n\r]+)/i],
  ["address", /registrant_contact_address\d*:\s*([^\n\r]+)/i],
  ["city", /registrant_contact_city:\s*([^\n\r]+)/i],
  ["registrantPostalCode", /registrant_contact_postalcode:\s*([^\n\r]+)/i],
  ["country", /registrant_contact_country:\s*([^\n\r]+)/i],
]);

export const nzParserOptions: ParserOptions = {
  regexMap: nzRegexMap,
  notFoundChecks: [
    (text) => text.includes("no matching objects"),
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .lu domains.
 */
export const luRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /domainname:\s*(.+)/i],
  ["creationDate", /registered:\s*(.+)/i],
  ["nameServers", /nserver:\s*(.+)/gi],
  ["status", /domaintype:\s*(.+)/i],
  ["registrar", /registrar-name:\s*(.+)/i],
  ["name", /org-name:\s*(.+)/i],
  ["address", /org-address:\s*(.+)/i],
  ["registrantPostalCode", /org-zipcode:\s*(.+)/i],
  ["city", /org-city:\s*(.+)/i],
  ["country", /org-country:\s*(.+)/i],
]);

export const luParserOptions: ParserOptions = {
  regexMap: luRegexMap,
  notFoundChecks: [
    (text) => text.includes("No such domain"),
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .cz domains.
 */
export const czRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /domain:\s*(.+)/i],
  ["name", /registrant:\s*(.+)/i],
  ["registrar", /registrar:\s*(.+)/i],
  ["creationDate", /registered:\s*(.+)/i],
  ["updatedDate", /changed:\s*(.+)/i],
  ["expirationDate", /expire:\s*(.+)/i],
  ["nameServers", /nserver:\s*(.+)/gi],
  ["status", /status:\s*(.+)/gi],
]);

export const czParserOptions: ParserOptions = {
  regexMap: czRegexMap,
  notFoundChecks: [
    (text) =>
      text.includes("% No entries found.") ||
      text.includes("Your connection limit exceeded"),
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .online domains.
 */
export const onlineRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /Domain Name:\s*(.+)/i],
  ["whoisServer", /Registrar WHOIS Server:\s*(.+)/i],
  ["registrar", /Registrar:\s*(.+)/i],
  ["registrarUrl", /Registrar URL:\s*(.+)/i],
  ["status", /Domain Status:\s*(.+)/gi],
  ["emails", /Registrant Email:\s*(.+)/i],
  ["nameServers", /Name Server:\s*(.+)/gi],
  ["creationDate", /Creation Date:\s*(.+)/i],
  ["expirationDate", /Registry Expiry Date:\s*(.+)/i],
  ["updatedDate", /Updated Date:\s*(.+)/i],
  ["dnssec", /DNSSEC:\s*([\S]+)/i],
]);

export const onlineParserOptions: ParserOptions = {
  regexMap: onlineRegexMap,
  notFoundChecks: [
    (text) => text.includes("Not found:"),
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .hr domains.
 */
export const hrRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /Domain Name:\s*(.+)/i],
  ["whoisServer", /Registrar WHOIS Server:\s*(.+)/i],
  ["registrarUrl", /Registrar URL:\s*(.+)/i],
  ["updatedDate", /Updated Date:\s*(.+)/i],
  ["creationDate", /Creation Date:\s*(.+)/i],
  ["expirationDate", /Registrar Registration Expiration Date:\s*(.+)/i],
  ["nameServers", /Name Server:\s*(.+)/gi],
  ["name", /Registrant Name:\s*(.+)/i],
  ["address", /Reigstrant Street:\s*(.+)/i],
]);

export const hrParserOptions: ParserOptions = {
  regexMap: hrRegexMap,
  notFoundChecks: [
    (text) => text.includes("ERROR: No entries found"),
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .hk domains.
 */
export const hkRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /Domain Name:\s*(.+)/i],
  ["status", /Domain Status:\s*(.+)/gi],
  ["dnssec", /DNSSEC:\s*(.+)/i],
  ["whoisServer", /Registrar WHOIS Server:\s*(.+)/i],
  ["registrarUrl", /Registrar URL:\s*(.+)/i],
  ["registrar", /Registrar Name:\s*(.+)/i],
  ["updatedDate", /Updated Date:\s*(.+)/i],
  ["creationDate", /Domain Name Commencement Date:\s*(.+)/i],
  ["expirationDate", /Expiry Date:\s*(.+)/i],
  ["nameServers", /Name Servers Information:\s+((?:.+\n)*)/i],
  // Only fields that exist in WhoisRecord are mapped.
]);

export const hkParserOptions: ParserOptions = {
  regexMap: hkRegexMap,
  notFoundChecks: [
    (text) =>
      text.includes("ERROR: No entries found") ||
      text.includes("The domain has not been registered"),
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .ua domains.
 */
export const uaRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /domain:\s*(.+)/i],
  ["status", /status:\s*(.+)/gi],
  ["registrar", /organization-loc:(.*)/i],
  ["registrarUrl", /url:(.*)/i],
  ["updatedDate", /modified:\s*(.+)/i],
  ["creationDate", /created:\s*(.+)/i],
  ["expirationDate", /expires:\s*(.+)/i],
  ["nameServers", /nserver:\s*(.+)/gi],
  [
    "emails",
    /[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?/gi,
  ],
]);

export const uaParserOptions: ParserOptions = {
  regexMap: uaRegexMap,
  notFoundChecks: [
    (text) => text.includes("ERROR: No entries found"),
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .укр domains.
 */
export const ukrRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /Domain name \(UTF8\):\s*(.+)/i],
  ["status", /Registry Status:\s*(.+)/i],
  ["registrar", /Registrar:\s*(.+)/i],
  ["registrarUrl", /Registrar URL:\s*(.+)/i],
  ["updatedDate", /Updated Date:\s*(.+)/i],
  ["creationDate", /Creation Date:\s*(.+)/i],
  ["expirationDate", /Expiration Date:\s*(.+)/i],
  ["nameServers", /Domain servers in listed order:\s+((?:.+\n)*)/i],
]);

export const ukrParserOptions: ParserOptions = {
  regexMap: ukrRegexMap,
  notFoundChecks: [
    (text) => text.includes("No match for domain"),
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .pp.ua domains.
 */
export const ppuaRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /Domain Name:\s*(.+)/i],
  ["status", /status:\s*(.+)/i],
  ["registrar", /Sponsoring Registrar:\s*(.+)/i],
  ["updatedDate", /Last Updated On:\s*(.+)/i],
  ["creationDate", /Created On:\s*(.+)/i],
  ["expirationDate", /Expiration Date:\s*(.+)/i],
  ["nameServers", /Name Server:\s*(.+)/gi],
]);

export const ppuaParserOptions: ParserOptions = {
  regexMap: ppuaRegexMap,
  notFoundChecks: [
    (text) => text.includes("No entries found."),
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .hn domains.
 */
export const hnRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /Domain Name:\s*(.+)/i],
  ["status", /Domain Status:\s*(.+)/gi],
  ["whoisServer", /WHOIS Server:\s*(.+)/i],
  ["registrarUrl", /Registrar URL:\s*(.+)/i],
  ["registrar", /Registrar:\s*(.+)/i],
  ["name", /Registrant Name:\s*(.+)/i],
  ["city", /Registrant City:\s*(.*)/i],
  ["address", /Registrant Street:\s*(.*)/i],
  ["state", /Registrant State\/Province:\s*(.*)/i],
  ["registrantPostalCode", /Registrant Postal Code:\s*(.*)/i],
  ["country", /Registrant Country:\s*(.+)/i],
  ["emails", /Registrant Email:\s*(.+)/i],
  ["updatedDate", /Updated Date:\s*(.+)/i],
  ["creationDate", /Creation Date:\s*(.+)/i],
  ["expirationDate", /Registry Expiry Date:\s*(.+)/i],
  ["nameServers", /Name Server:\s*(.+)/gi],
]);

export const hnParserOptions: ParserOptions = {
  regexMap: hnRegexMap,
  notFoundChecks: [
    (text) => text.trim() === "No matching record.",
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .lat domains.
 */
export const latRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /Domain Name:\s*(.+)/i],
  ["status", /Domain Status:\s*(.+)/gi],
  ["whoisServer", /Registrar WHOIS Server:\s*(.+)/i],
  ["registrarUrl", /Registrar URL:\s*(.+)/i],
  ["registrar", /Registrar:\s*(.+)/i],
  ["emails", /Registrant Email:\s*(.+)/i],
  ["name", /Registrant Name:\s*(.+)/i],
  ["city", /Registrant City:\s*(.*)/i],
  ["address", /Registrant Street:\s*(.*)/i],
  ["state", /Registrant State\/Province:\s*(.*)/i],
  ["registrantPostalCode", /Registrant Postal Code:\s*(.*)/i],
  ["country", /Registrant Country:\s*(.+)/i],
  ["updatedDate", /Updated Date:\s*(.+)/i],
  ["creationDate", /Creation Date:\s*(.+)/i],
  ["expirationDate", /Registry Expiry Date:\s*(.+)/i],
  ["nameServers", /Name Server:\s*(.+)/gi],
]);

export const latParserOptions: ParserOptions = {
  regexMap: latRegexMap,
  notFoundChecks: [
    (text) => text.trim() === "No matching record.",
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .cn domains.
 */
export const cnRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /Domain Name:\s*(.+)/i],
  ["registrar", /Registrar:\s*(.+)/i],
  ["creationDate", /Registration Time:\s*(.+)/i],
  ["expirationDate", /Expiration Time:\s*(.+)/i],
  ["nameServers", /Name Server:\s*(.+)/gi],
  ["status", /Status:\s*(.+)/gi],
  [
    "emails",
    /[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?/gi,
  ],
  ["dnssec", /dnssec:\s*([\S]+)/i],
  ["name", /Registrant:\s*(.+)/i],
]);

export const cnParserOptions: ParserOptions = {
  regexMap: cnRegexMap,
  notFoundChecks: [
    (text) => text.trim() === "No matching record.",
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .app domains.
 */
export const appRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /Domain Name:\s*(.+)/i],
  ["registrar", /Registrar:\s*(.+)/i],
  ["whoisServer", /Whois Server:\s*(.+)/i],
  ["updatedDate", /Updated Date:\s*(.+)/i],
  ["creationDate", /Creation Date:\s*(.+)/i],
  ["expirationDate", /Expir\w+ Date:\s*(.+)/i],
  ["nameServers", /Name Server:\s*(.+)/gi],
  ["status", /Status:\s*(.+)/gi],
  [
    "emails",
    /[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?/gi,
  ],
  ["dnssec", /dnssec:\s*([\S]+)/i],
  ["name", /Registrant Name:\s*(.+)/i],
  ["org", /Registrant\s*Organization:\s*(.+)/i],
  ["address", /Registrant Street:\s*(.+)/i],
  ["city", /Registrant City:\s*(.+)/i],
  ["state", /Registrant State\/Province:\s*(.+)/i],
  ["registrantPostalCode", /Registrant Postal Code:\s*(.+)/i],
  ["country", /Registrant Country:\s*(.+)/i],
]);

export const appParserOptions: ParserOptions = {
  regexMap: appRegexMap,
  notFoundChecks: [
    (text) => text.trim() === "Domain not found.",
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .money domains.
 */
export const moneyRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /Domain Name:\s*(.+)/i],
  ["registrar", /Registrar:\s*(.+)/i],
  ["whoisServer", /Registrar WHOIS Server:\s*(.+)/i],
  ["updatedDate", /Updated Date:\s*(.+)/i],
  ["creationDate", /Creation Date:\s*(.+)/i],
  ["expirationDate", /Registry Expiry Date:\s*(.+)/i],
  ["nameServers", /Name Server:\s*(.+)/gi],
  ["status", /Domain Status:\s*(.+)/gi],
  [
    "emails",
    /[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?/gi,
  ],
  ["dnssec", /DNSSEC:\s*(.+)/i],
  ["name", /Registrant Name:\s*(.+)/i],
  ["org", /Registrant Organization:\s*(.+)/i],
  ["address", /Registrant Street:\s*(.+)/i],
  ["city", /Registrant City:\s*(.+)/i],
  ["state", /Registrant State\/Province:\s*(.+)/i],
  ["registrantPostalCode", /Registrant Postal Code:\s*(.+)/i],
  ["country", /Registrant Country:\s*(.+)/i],
]);

export const moneyParserOptions: ParserOptions = {
  regexMap: moneyRegexMap,
  notFoundChecks: [
    (text) => text.trim() === "Domain not found.",
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .ar domains.
 */
export const arRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /domain:\s*(.+)/i],
  ["registrar", /registrar:\s*(.+)/i],
  ["whoisServer", /whois:\s*(.+)/i],
  ["updatedDate", /changed:\s*(.+)/i],
  ["creationDate", /created:\s*(.+)/i],
  ["expirationDate", /expire:\s*(.+)/i],
  ["nameServers", /nserver:\s*(.+) \(.*\)/gi],
  ["status", /Domain Status:\s*(.+)/gi],
  [
    "emails",
    /[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?/gi,
  ],
  ["name", /name:\s*(.+)/i],
]);

export const arParserOptions: ParserOptions = {
  regexMap: arRegexMap,
  notFoundChecks: [
    (text) =>
      text.trim() === "El dominio no se encuentra registrado en NIC Argentina",
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .by domains.
 */
export const byRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /Domain name:\s*(.+)/i],
  ["registrar", /Registrar:\s*(.+)/i],
  ["updatedDate", /Update Date:\s*(.+)/i],
  ["creationDate", /Creation Date:\s*(.+)/i],
  ["expirationDate", /Expiration Date:\s*(.+)/i],
  ["nameServers", /Name Server:\s*(.+)/gi],
  ["status", /Domain Status:\s*(.+)/gi],
  ["name", /Person:\s*(.+)/i],
  ["org", /Org:\s*(.+)/i],
  ["country", /Country:\s*(.+)/i],
  ["address", /Address:\s*(.+)/i],
  // phone not mapped, not in WhoisRecord
]);

export const byParserOptions: ParserOptions = {
  regexMap: byRegexMap,
  notFoundChecks: [
    (text) => text.trim() === "Object does not exist",
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .cr domains.
 */
export const crRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /domain:\s*(.+)/i],
  ["name", /name:\s*(.+)/i],
  ["registrar", /registrar:\s*(.+)/i],
  ["updatedDate", /changed:\s*(.+)/i],
  ["creationDate", /registered:\s*(.+)/i],
  ["expirationDate", /expire:\s*(.+)/i],
  ["nameServers", /nserver:\s*(.+)/gi],
  ["status", /status:\s*(.+)/gi],
  ["org", /org:\s*(.+)/i],
  ["address", /address:\s*(.+)/i],
  // phone not mapped, not in WhoisRecord
]);

export const crParserOptions: ParserOptions = {
  regexMap: crRegexMap,
  notFoundChecks: [
    (text) => text.trim() === "El dominio no existe.",
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .ve domains.
 */
export const veRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /Nombre de Dominio:\s*(.+)/i],
  ["status", /Estatus del dominio:\s*(.+)/i],
  ["registrar", /registrar:\s*(.+)/i],
  ["updatedDate", /Ultima Actualización:\s*(.+)/i],
  ["creationDate", /Fecha de Creación:\s*(.+)/i],
  ["expirationDate", /Fecha de Vencimiento:\s*(.+)/i],
  ["nameServers", /Nombres de Dominio:((?:\s+- .*)*)/i],
  ["name", /Titular:\s*(?:.*\n){1}\s+(.*)/i],
  ["city", /Titular:\s*(?:.*\n){3}\s+([\s\w]*)/i],
  ["address", /Titular:\s*(?:.*\n){2}\s+(.*)/i],
  ["state", /Titular:\s*(?:.*\n){3}\s+.*?,(.*),/i],
  ["country", /Titular:\s*(?:.*\n){3}\s+.*, .+ {2}(.*)/i],
  ["emails", /Titular:\s*.*\t(.*)/i],
]);

export const veParserOptions: ParserOptions = {
  regexMap: veRegexMap,
  notFoundChecks: [
    (text) => text.trim() === "El dominio no existe.",
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .do domains.
 */
export const doRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /Domain Name:\s*(.+)/i],
  ["whoisServer", /WHOIS Server:\s*(.+)/i],
  ["registrar", /Registrar:\s*(.+)/i],
  ["status", /Domain Status:\s*(.+)/gi],
  ["name", /Registrant Name:\s*(.+)/i],
  ["org", /Registrant Organization:\s*(.+)/i],
  ["address", /Registrant Street:\s*(.+)/i],
  ["city", /Registrant City:\s*(.+)/i],
  ["state", /Registrant State\/Province:\s*(.+)/i],
  ["registrantPostalCode", /Registrant Postal Code:\s*(.+)/i],
  ["country", /Registrant Country:\s*(.+)/i],
  ["emails", /Registrant Email:\s*(.+)/i],
  ["creationDate", /Creation Date:\s*(.+)/i],
  ["expirationDate", /Registry Expiry Date:\s*(.+)/i],
  ["updatedDate", /Updated Date:\s*(.+)/i],
  ["nameServers", /Name Server:\s*(.+)/gi],
  ["dnssec", /DNSSEC:\s*(.+)/i],
]);

export const doParserOptions: ParserOptions = {
  regexMap: doRegexMap,
  notFoundChecks: [
    (text) => text.trim() === "Extensión de dominio no válido.",
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .ae domains.
 */
export const aeRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /Domain Name:\s*(.+)/i],
  ["status", /Status:\s*(.+)/i],
  ["name", /Registrant Contact Name:\s*(.+)/i],
  // Tech Contact Name is not in WhoisRecord, so omitted
]);

export const aeParserOptions: ParserOptions = {
  regexMap: aeRegexMap,
  notFoundChecks: [
    (text) => text.trim() === "No Data Found",
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .si domains.
 */
export const siRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /domain:\s*(.+)/i],
  ["registrar", /registrar:\s*(.+)/i],
  ["nameServers", /nameserver:\s*(.+)/gi],
  ["name", /registrant:\s*(.+)/i],
  ["creationDate", /created:\s*(.+)/i],
  ["expirationDate", /expire:\s*(.+)/i],
]);

export const siParserOptions: ParserOptions = {
  regexMap: siRegexMap,
  notFoundChecks: [
    (text) => text.includes("No entries found for the selected source(s)."),
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .no domains.
 */
export const noRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /Domain Name.*:\s*(.+)/i],
  ["creationDate", /Additional information:\nCreated:\s*(.+)/i],
  ["updatedDate", /Additional information:\n(?:.*\n)Last updated:\s*(.+)/i],
]);

export const noParserOptions: ParserOptions = {
  regexMap: noRegexMap,
  notFoundChecks: [
    (text) => text.includes("No match"),
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .kz domains.
 */
export const kzRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /Domain Name............:\s*(.+)/i],
  ["registrar", /Current Registr?ar:\s*(.+)/i],
  ["creationDate", /Domain created:\s*(.+)/i],
  ["updatedDate", /Last modified\s*:\s*(.+)/i],
  ["nameServers", /server.*:\s*(.+)/gi],
  ["status", / (.+?) -/g],
  [
    "emails",
    /[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?/gi,
  ],
  ["org", /Organization Name.*:\s*(.+)/i],
]);

export const kzParserOptions: ParserOptions = {
  regexMap: kzRegexMap,
  notFoundChecks: [
    (text) => text.includes("*** Nothing found for this query."),
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .ir domains.
 */
export const irRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /domain:\s*(.+)/i],
  ["name", /person:\s*(.+)/i],
  ["org", /org:\s*(.+)/i],
  ["updatedDate", /last-updated:\s*(.+)/i],
  ["expirationDate", /expire-date:\s*(.+)/i],
  ["nameServers", /nserver:\s*(.+)/gi],
  [
    "emails",
    /[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?/gi,
  ],
]);

export const irParserOptions: ParserOptions = {
  regexMap: irRegexMap,
  notFoundChecks: [
    (text) => text.includes('No match for "'),
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .life domains.
 */
export const lifeRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /Domain Name::\s*(.+)/i],
  ["registrar", /Registrar:\s*(.+)/i],
  ["updatedDate", /Updated Date:\s*(.+)/i],
  ["creationDate", /Creation Date:\s*(.+)/i],
  ["expirationDate", /Registry Expiry Date:\s*(.+)/i],
  ["nameServers", /Name Server:\s*(.+)/gi],
  [
    "emails",
    /[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?/gi,
  ],
]);

export const lifeParserOptions: ParserOptions = {
  regexMap: lifeRegexMap,
  notFoundChecks: [
    (text) => text.includes("Domain not found."),
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .中国 (.xn--fiqs8s) domains.
 */
export const zhongguoRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /Domain Name:\s*(.+)/i],
  ["creationDate", /Registration Time:\s*(.+)/i],
  ["name", /Registrant:\s*(.+)/i],
  ["registrar", /Sponsoring Registrar:\s*(.+)/i],
  ["expirationDate", /Expiration Time:\s*(.+)/i],
  ["nameServers", /Name Server:\s*(.+)/gi],
  [
    "emails",
    /[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?/gi,
  ],
]);

export const zhongguoParserOptions: ParserOptions = {
  regexMap: zhongguoRegexMap,
  notFoundChecks: [
    (text) => text.includes('No match for "'),
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .ml domains.
 */
export const mlRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /Domain name:\s*([^(i|\n)]+)/i],
  ["registrar", /Organization:\s*(.+)/i],
  ["creationDate", /Domain registered:\s*(.+)/i],
  ["expirationDate", /Record will expire on:\s*(.+)/i],
  ["nameServers", /Domain Nameservers:\s+((?:.+\n)*)/i],
  [
    "emails",
    /[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?/gi,
  ],
]);

export const mlParserOptions: ParserOptions = {
  regexMap: mlRegexMap,
  notFoundChecks: [
    (text) =>
      text.includes(
        "Invalid query or domain name not known in the Point ML Domain Registry",
      ),
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .za domains.
 */
export const zaRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /Domain Name:\s*(.+)/i],
  ["whoisServer", /Registrar WHOIS Server:\s*(.+)/i],
  ["registrar", /Registrar:\s*(.+)/i],
  ["registrarUrl", /Registrar URL:\s*(.+)/i],
  ["status", /Domain Status:\s*(.+)/gi],
  ["name", /Registrant Name:\s*(.+)/i],
  ["org", /Registrant Organization:\s*(.+)/i],
  ["address", /Registrant Street:\s*(.+)/i],
  ["city", /Registrant City:\s*(.+)/i],
  ["state", /Registrant State\/Province:\s*(.+)/i],
  ["registrantPostalCode", /Registrant Postal Code:\s*(.+)/i],
  ["country", /Registrant Country:\s*(.+)/i],
  ["emails", /Registrant Email:\s*(.+)/i],
  ["creationDate", /Creation Date:\s*(.+)/i],
  ["expirationDate", /Registry Expiry Date:\s*(.+)/i],
  ["updatedDate", /Updated Date:\s*(.+)/i],
  ["nameServers", /Name Server:\s*(.+)/gi],
]);

export const zaParserOptions: ParserOptions = {
  regexMap: zaRegexMap,
  notFoundChecks: [
    (text) => text.startsWith("Available"),
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .gg domains.
 */
export const ggRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /Domain:\n +(.+)/i],
  ["registrar", /Registrar:\n\s+(.+)/i],
  ["creationDate", /Relevant dates:\n\s+Registered on (.+)/i],
]);

export const ggParserOptions: ParserOptions = {
  regexMap: ggRegexMap,
  notFoundChecks: [
    (text) => text.includes("NOT FOUND"),
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .bw domains.
 */
export const bwRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /Domain Name\.*: *(.+)/i],
  ["creationDate", /Creation Date: (.+)/i],
  ["registrar", /Registrar: (.+)/i],
  ["name", /RegistrantName: *(.+)/i],
  ["org", /RegistrantOrganization: (.+)/i],
  ["address", /RegistrantStreet: *(.+)/i],
  ["city", /RegistrantCity: *(.+)/i],
  ["country", /RegistrantCountry\.*: *(.+)/i],
  ["emails", /RegistrantEmail\.*: *(.+)/i],
  ["nameServers", /Name Server\.*: *(.+)/gi],
  ["dnssec", /dnssec\.*: *(.+)/i],
]);

export const bwParserOptions: ParserOptions = {
  regexMap: bwRegexMap,
  notFoundChecks: [
    (text) => text.includes("not registered"),
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .tn domains.
 */
export const tnRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /Domain name.*: (.+)/i],
  ["registrar", /Registrar.*: (.+)/i],
  ["creationDate", /Creation date.*: (.+)/i],
  ["status", /Domain status.*: (.+)/i],
  ["name", /Owner Contact\nName.*: (.+)/i],
  ["address", /Owner Contact\n.*:.*\n.*\n.*: (.+)/i],
  ["city", /Owner Contact\n.*:.*\n.*\n.*\n.*: (.+)/i],
  ["state", /Owner Contact\n.*:.*\n.*\n.*\n.*\n.*\n.*: (.+)/i],
  [
    "registrantPostalCode",
    /Owner Contact\n.*:.*\n.*\n.*\n.*\n.*\n.*\n.*: (.+)/i,
  ],
  ["country", /Owner Contact\n.*:.*\n.*\n.*\n.*\n.*\n.*\n.*\n.*: (.+)/i],
  [
    "emails",
    /Owner Contact\n.*:.*\n.*\n.*\n.*\n.*\n.*\n.*\n.*\n.*\n.*\n.*:(.+)/i,
  ],
  ["nameServers", /servers\nName.*: (.+)(?:\nName.*:)? (.+)/i],
]);

export const tnParserOptions: ParserOptions = {
  regexMap: tnRegexMap,
  notFoundChecks: [
    (text) => text.startsWith("Available"),
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .site domains.
 */
export const siteRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /Domain Name: *(.+)/i],
  ["registrar", /Registrar: *(.+)/i],
  ["whoisServer", /Whois Server: *(.+)/i],
  ["updatedDate", /Updated Date: *(.+)/i],
  ["creationDate", /Creation Date: *(.+)/i],
  ["expirationDate", /Registry Expiry Date: *(.+)/i],
  ["nameServers", /Name Server: *(.+)/gi],
  ["status", /Domain Status: *(.+)/gi],
  [
    "emails",
    /[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?/gi,
  ],
  ["dnssec", /DNSSEC: *([\S]+)/i],
  ["name", /Registrant Name: *(.+)/i],
  ["org", /Registrant\s*Organization: *(.+)/i],
  ["address", /Registrant Street: *(.+)/i],
  ["city", /Registrant City: *(.+)/i],
  ["state", /Registrant State\/Province: *(.+)/i],
  ["registrantPostalCode", /Registrant Postal Code: *(.+)/i],
  ["country", /Registrant Country: *(.+)/i],
]);

export const siteParserOptions: ParserOptions = {
  regexMap: siteRegexMap,
  notFoundChecks: [
    (text) => text.includes("DOMAIN NOT FOUND"),
    ...defaultParserOptions.notFoundChecks,
  ],
};

/**
 * Specific regex map for .design domains.
 */
export const designRegexMap: Map<keyof WhoisRecord, RegExp> = new Map([
  ["domainName", /Domain Name: *(.+)/i],
  ["registrarUrl", /Registrar URL: *(.+)/i],
  ["whoisServer", /Registrar WHOIS Server: *(.+)/i],
  ["updatedDate", /Updated Date: *(.+)/i],
  ["creationDate", /Creation Date: *(.+)/i],
  ["expirationDate", /Registry Expiry Date: *(.+)/i],
  ["nameServers", /Name Server: *(.+)/gi],
  ["status", /Domain Status: *(.+)/gi],
  [
    "emails",
    /[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?/gi,
  ],
  ["dnssec", /DNSSEC: *([\S]+)/i],
  ["name", /Registrant Name: *(.+)/i],
  ["org", /Registrant\s*Organization: *(.+)/i],
  ["address", /Registrant Street: *(.+)/i],
  ["city", /Registrant City: *(.+)/i],
  ["state", /Registrant State\/Province: *(.+)/i],
  ["registrantPostalCode", /Registrant Postal Code: *(.+)/i],
  ["country", /Registrant Country: *(.+)/i],
]);

export const designParserOptions: ParserOptions = {
  regexMap: designRegexMap,
  notFoundChecks: [
    (text) => text.includes("No Data Found"),
    ...defaultParserOptions.notFoundChecks,
  ],
};
