# Catalog sources and licences

The catalog under `unlist/catalog/` is MIT like the rest of the project, with these inputs:

| Source | Used for | Licence | How it enters |
| --- | --- | --- | --- |
| [California CPPA Data Broker Registry](https://cppa.ca.gov/data_broker_registry/) (`registry.csv`) | `registry/cppa.yaml`: every registered broker's name, DBA, website, contact email, postal address, privacy-rights page, disclosure flags | Public record published by a California state agency | `unlist catalog import-registry --cppa registry.csv` |
| [The Markup / CalMatters opt-out pages dataset](https://github.com/the-markup/investigation-data-broker-opt-out-pages) | Checked opt-out URL per registrant and whether the page was hidden from search engines | Apache-2.0 | `--markup data-broker-opt-out-pages.csv` on the same command |
| [thumpersecure/opt-out-manual-2026](https://github.com/thumpersecure/opt-out-manual-2026) (`The.Manual.md`) | `registry/optout-manual.yaml`: 437 people-search sites and brokers with opt-out link, method, what the site demands, category | Unlicense (public domain) | `unlist catalog import-manual --manual The.Manual.md` |
| Each broker's own opt-out and privacy pages | `brokers/*.yaml` (curated people-search and marketing entries) | Facts about a public page | Written by hand, URL in `sources`, `last_verified` set when the page was last checked |

Read but not copied, because their licences do not allow redistribution in an MIT project
or are all-rights-reserved. Good further reading when an entry here is stale:

- Yael Grauer's [Big Ass Data Broker Opt-Out List](https://github.com/yaelwrites/Big-Ass-Data-Broker-Opt-Out-List) (CC BY-NC-SA)
- Privacy Rights Clearinghouse [data broker registry report](https://privacyrights.org/data-brokers) (CC BY-NC-SA)
- IntelTechniques [workbook](https://inteltechniques.com/workbook.html) (all rights reserved)

Nothing in the catalog is personal data. Operator additions go in `~/.unlist/catalog/*.yaml`
and are not part of the repo.

Rows for the same company in the two generated files are merged at load time: the state registry
row keeps its id, registry number and postal address; the manual supplies the opt-out link, method
and category. Curated entries override both and inherit a way out when they only describe search.
