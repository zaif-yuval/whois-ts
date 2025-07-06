import whois from "whois";
import { WhoisParser } from "./parser";
import { WhoisRecord, ParserOptions } from "./types";
import * as tldRegex from "./tldRegex";
import { WhoisDomainNotFoundError } from "./errors";

function getParserOptions(domain: string): ParserOptions {
  if (domain.endsWith(".com")) return tldRegex.comParserOptions;
  if (domain.endsWith(".net")) return tldRegex.netParserOptions;
  if (domain.endsWith(".org")) return tldRegex.orgParserOptions;
  if (domain.endsWith(".pe")) return tldRegex.peParserOptions;
  if (domain.endsWith(".cl")) return tldRegex.clParserOptions;
  if (domain.endsWith(".sg")) return tldRegex.sgParserOptions;
  if (domain.endsWith(".ro")) return tldRegex.roParserOptions;
  if (domain.endsWith(".nl")) return tldRegex.nlParserOptions;
  if (domain.endsWith(".lt")) return tldRegex.ltParserOptions;
  if (domain.endsWith(".fi")) return tldRegex.fiParserOptions;
  if (domain.endsWith(".hr")) return tldRegex.hrParserOptions;
  if (domain.endsWith(".name")) return tldRegex.nameParserOptions;
  if (domain.endsWith(".me")) return tldRegex.meParserOptions;
  if (domain.endsWith(".ae")) return tldRegex.aeParserOptions;
  if (domain.endsWith(".au")) return tldRegex.auParserOptions;
  if (domain.endsWith(".ru")) return tldRegex.ruParserOptions;
  if (domain.endsWith(".us")) return tldRegex.usParserOptions;
  if (domain.endsWith(".uk")) return tldRegex.ukParserOptions;
  if (domain.endsWith(".fr")) return tldRegex.frParserOptions;
  if (domain.endsWith(".pl")) return tldRegex.plParserOptions;
  if (domain.endsWith(".ca")) return tldRegex.caParserOptions;
  if (domain.endsWith(".br")) return tldRegex.brParserOptions;
  if (domain.endsWith(".eu")) return tldRegex.euParserOptions;
  if (domain.endsWith(".ee")) return tldRegex.eeParserOptions;
  if (domain.endsWith(".kr")) return tldRegex.krParserOptions;
  if (domain.endsWith(".pt")) return tldRegex.ptParserOptions;
  if (domain.endsWith(".bg")) return tldRegex.bgParserOptions;
  if (domain.endsWith(".de")) return tldRegex.deParserOptions;
  if (domain.endsWith(".at")) return tldRegex.atParserOptions;
  if (domain.endsWith(".be")) return tldRegex.beParserOptions;
  if (domain.endsWith(".рф")) return tldRegex.rfParserOptions;
  if (domain.endsWith(".info")) return tldRegex.infoParserOptions;
  if (domain.endsWith(".su")) return tldRegex.suParserOptions;
  if (domain.endsWith(".si")) return tldRegex.siParserOptions;
  if (domain.endsWith(".kg")) return tldRegex.kgParserOptions;
  if (domain.endsWith(".io")) return tldRegex.ioParserOptions;
  if (domain.endsWith(".biz")) return tldRegex.bizParserOptions;
  if (domain.endsWith(".mobi")) return tldRegex.mobiParserOptions;
  if (domain.endsWith(".ch") || domain.endsWith(".li"))
    return tldRegex.chliParserOptions;
  if (domain.endsWith(".id")) return tldRegex.idParserOptions;
  if (domain.endsWith(".sk")) return tldRegex.skParserOptions;
  if (domain.endsWith(".se") || domain.endsWith(".nu"))
    return tldRegex.seParserOptions;
  if (domain.endsWith(".no")) return tldRegex.noParserOptions;
  if (domain.endsWith(".is")) return tldRegex.isParserOptions;
  if (domain.endsWith(".dk")) return tldRegex.dkParserOptions;
  if (domain.endsWith(".it")) return tldRegex.itParserOptions;
  if (domain.endsWith(".mx")) return tldRegex.mxParserOptions;
  if (domain.endsWith(".ai")) return tldRegex.aiParserOptions;
  if (domain.endsWith(".il")) return tldRegex.ilParserOptions;
  if (domain.endsWith(".in")) return tldRegex.inParserOptions;
  if (domain.endsWith(".cat")) return tldRegex.catParserOptions;
  if (domain.endsWith(".ie")) return tldRegex.ieParserOptions;
  if (domain.endsWith(".nz")) return tldRegex.nzParserOptions;
  if (domain.endsWith(".lu")) return tldRegex.luParserOptions;
  if (domain.endsWith(".cz")) return tldRegex.czParserOptions;
  if (domain.endsWith(".online")) return tldRegex.onlineParserOptions;
  if (domain.endsWith(".cn")) return tldRegex.cnParserOptions;
  if (domain.endsWith(".app")) return tldRegex.appParserOptions;
  if (domain.endsWith(".money")) return tldRegex.moneyParserOptions;
  if (domain.endsWith(".ar")) return tldRegex.arParserOptions;
  if (domain.endsWith(".by")) return tldRegex.byParserOptions;
  if (domain.endsWith(".cr")) return tldRegex.crParserOptions;
  if (domain.endsWith(".do")) return tldRegex.doParserOptions;
  if (domain.endsWith(".jobs")) return tldRegex.jobsParserOptions;
  if (domain.endsWith(".lat")) return tldRegex.latParserOptions;
  if (domain.endsWith(".sa")) return tldRegex.saParserOptions;
  if (domain.endsWith(".tw")) return tldRegex.twParserOptions;
  if (domain.endsWith(".tr")) return tldRegex.trParserOptions;
  if (domain.endsWith(".ve")) return tldRegex.veParserOptions;
  if (domain.endsWith(".ua"))
    return domain.endsWith(".pp.ua")
      ? tldRegex.ppuaParserOptions
      : tldRegex.uaParserOptions;
  if (domain.endsWith(".укр") || domain.endsWith(".xn--j1amh"))
    return tldRegex.ukrParserOptions;
  if (domain.endsWith(".kz")) return tldRegex.kzParserOptions;
  if (domain.endsWith(".ir")) return tldRegex.irParserOptions;
  if (domain.endsWith(".中国") || domain.endsWith(".xn--fiqs8s"))
    return tldRegex.zhongguoParserOptions;
  if (domain.endsWith(".ml")) return tldRegex.mlParserOptions;
  if (domain.endsWith(".group")) return tldRegex.groupParserOptions;
  if (domain.endsWith(".za")) return tldRegex.zaParserOptions;
  if (domain.endsWith(".bw")) return tldRegex.bwParserOptions;
  if (domain.endsWith(".bz")) return tldRegex.bzParserOptions;
  if (domain.endsWith(".gg")) return tldRegex.ggParserOptions;
  if (domain.endsWith(".city")) return tldRegex.cityParserOptions;
  if (domain.endsWith(".design")) return tldRegex.designParserOptions;
  if (domain.endsWith(".studio")) return tldRegex.studioParserOptions;
  if (domain.endsWith(".style")) return tldRegex.styleParserOptions;
  if (domain.endsWith(".life")) return tldRegex.lifeParserOptions;
  if (domain.endsWith(".tn")) return tldRegex.tnParserOptions;
  if (domain.endsWith(".rs")) return tldRegex.rsParserOptions;
  if (domain.endsWith(".site")) return tldRegex.siteParserOptions;
  if (domain.endsWith(".рус") || domain.endsWith(".xn--p1acf"))
    return tldRegex.pycParserOptions;
  if (domain.endsWith(".hk")) return tldRegex.hkParserOptions;
  if (domain.endsWith(".club")) return tldRegex.clubParserOptions;
  if (domain.endsWith(".jp")) return tldRegex.jpParserOptions;
  if (domain.endsWith(".space")) return tldRegex.spaceParserOptions;
  if (domain.endsWith(".hn")) return tldRegex.hnParserOptions;
  return tldRegex.defaultParserOptions;
}

export async function fetchAndParseWhois(domain: string): Promise<WhoisRecord> {
  return new Promise((resolve, reject) => {
    whois.lookup(domain, (err: Error | null, data: string) => {
      if (err) return reject(err);
      try {
        const options = getParserOptions(domain);
        const parser = new WhoisParser(data, options);
        resolve(parser.data);
      } catch (e) {
        reject(e);
      }
    });
  });
}

export type { WhoisRecord };
export { WhoisDomainNotFoundError };
