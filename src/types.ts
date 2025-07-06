export interface WhoisRecord {
  domainName?: string;
  registrar?: string;
  registrarUrl?: string;
  reseller?: string;
  whoisServer?: string;
  referralUrl?: string;
  updatedDate?: Date;
  creationDate?: Date;
  expirationDate?: Date;
  nameServers?: string[];
  status?: string[];
  emails?: string[];
  dnssec?: string;
  name?: string;
  org?: string;
  address?: string;
  city?: string;
  state?: string;
  registrantPostalCode?: string;
  country?: string;
}

export interface ParserOptions {
  regexMap: Map<keyof WhoisRecord, RegExp>;
  notFoundChecks: ((text: string) => boolean)[];
}
