export class WhoisDomainNotFoundError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "WhoisDomainNotFoundError";
  }
}
