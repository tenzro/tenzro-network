//! Provider-side territorial exclusion for restricted-licence models.
//!
//! Some model licences grant rights only outside named territories. MiniMax
//! H3's is the first this node serves: "worldwide, excluding the European
//! Union, the United Kingdom, the Republic of Korea and the United States of
//! America", with §V.4 extending the exclusion to the model's **outputs**, and
//! §V.5 requiring "reasonable and proportionate technical and organizational
//! safeguards".
//!
//! Because outputs are in scope and the licence grants no end-user carve-out,
//! serving an inference to an excluded territory is itself outside the grant.
//! That is what forces a per-request check rather than a registration-time one.
//!
//! ## What this is not
//!
//! Not a security control. A determined user with a VPN defeats it, and that is
//! accepted rather than a defect: the standard is proportionality, not
//! invulnerability. What the check has to be is *honest* — current data, no
//! spoofable input treated as authoritative, and a decision recorded so the
//! effort is evidenced rather than merely asserted.
//!
//! The primary control is the operator's acceptance of the licence terms; this
//! is the technical backstop that makes the acceptance meaningful.

use std::net::IpAddr;

use tenzro_types::model::{TerritorialGrant, TerritoryDecision, TerritorySource};

/// Why a request was refused, phrased for the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TerritoryRefusal {
    /// The caller's territory is outside the licence's grant.
    Excluded { country: String },
    /// The territory could not be established, and an unresolvable request
    /// cannot be shown to be inside the grant.
    Unresolved { reason: &'static str },
}

impl TerritoryRefusal {
    /// A message that tells the caller what happened and what would change it.
    pub fn message(&self, model_id: &str) -> String {
        match self {
            Self::Excluded { country } => format!(
                "{model_id} is licensed for use outside {country}; this node cannot serve it \
                 to callers there"
            ),
            Self::Unresolved { reason } => format!(
                "{model_id} is licensed by territory and this node could not establish the \
                 caller's ({reason}), so it cannot serve the request"
            ),
        }
    }
}

/// Establish the client address for an access-control decision.
///
/// ⛔ **The leftmost `X-Forwarded-For` entry is attacker-controlled.** Any
/// client can prepend a value, so taking `[0]` turns this whole control into a
/// no-op — a mistake with its own CVE class. The correct algorithm for an
/// enforcement decision walks the chain **right to left**, discarding addresses
/// contributed by proxies we operate, and takes the first address outside that
/// set: the nearest hop we did not put there.
///
/// `trusted` is the operator's list of reverse-proxy addresses. With an empty
/// list nothing in the header is trustworthy, so the header is ignored entirely
/// and the socket address is used.
pub fn client_ip_for_enforcement(
    forwarded_for: Option<&str>,
    socket_addr: Option<IpAddr>,
    trusted: &[IpAddr],
) -> Option<IpAddr> {
    // No configured proxy means no reason to believe any header.
    if trusted.is_empty() {
        return socket_addr;
    }
    // The peer we are actually talking to must itself be a trusted proxy before
    // anything it forwarded is worth reading.
    match socket_addr {
        Some(peer) if trusted.contains(&peer) => {}
        other => return other,
    }
    if let Some(header) = forwarded_for {
        for candidate in header.split(',').rev() {
            let Ok(ip) = candidate.trim().parse::<IpAddr>() else {
                // An unparseable entry breaks the chain: everything to its left
                // was contributed by something we cannot vouch for.
                break;
            };
            if !trusted.contains(&ip) {
                return Some(ip);
            }
        }
    }
    socket_addr
}

/// Normalise an address before a database lookup.
///
/// IPv4-mapped IPv6 (`::ffff:a.b.c.d`) is the classic bypass: the mapped form
/// misses an IPv4 lookup and reads as an unknown v6 address. Unmap it so both
/// spellings of one address resolve identically.
pub fn normalize_for_lookup(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

/// Whether an address is one this node cannot geolocate in principle.
pub fn is_local(ip: IpAddr) -> bool {
    match normalize_for_lookup(ip) {
        IpAddr::V4(v4) => {
            v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                // fc00::/7 unique-local and fe80::/10 link-local. `is_unicast_link_local`
                // and `is_unique_local` are unstable, so match the prefixes directly.
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// How the operator has chosen to treat callers this node cannot geolocate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LocalCallerPolicy {
    /// Refuse, like any other unresolvable caller. The safe default.
    #[default]
    Refuse,
    /// The operator declares that local callers are inside the grant. An
    /// attestation about their own deployment, recorded as one — not a bypass.
    DeclareInside,
}

/// The territory resolution for one request.
pub struct ResolvedTerritory {
    pub country: Option<String>,
    pub source: TerritorySource,
}

/// Decide whether a request may be served, and produce the record of it.
///
/// **Fails closed**, and the asymmetry is why: serving outside the grant is a
/// breach that can cost the right to serve the model at all, while refusing a
/// resolvable-but-unresolved request costs one response. Note this is the
/// opposite default from a security control, where fail-open is often right.
///
/// 🔑 Callers must scope this to the model. A node with no geo database must
/// lose its *restricted* models, never its unrestricted ones — otherwise the
/// control is too expensive to keep, and an operator has an incentive to delete
/// the database to bring the node back up.
pub fn decide(
    model_id: &str,
    license_id: &str,
    grant: &TerritorialGrant,
    resolved: &ResolvedTerritory,
    database: &str,
    now: u64,
) -> (Result<(), TerritoryRefusal>, TerritoryDecision) {
    let verdict = match &resolved.country {
        Some(country) if grant.excludes(country) => Err(TerritoryRefusal::Excluded {
            country: country.clone(),
        }),
        Some(_) => Ok(()),
        None => Err(TerritoryRefusal::Unresolved {
            reason: match resolved.source {
                TerritorySource::Unknown => "no location could be determined",
                TerritorySource::PeerAsserted => "the relaying peer asserted no location",
                TerritorySource::IpGeo => "the address is not in the location database",
                TerritorySource::OperatorDeclared => "no operator declaration applies",
            },
        }),
    };
    let record = TerritoryDecision {
        model_id: model_id.to_string(),
        license_id: license_id.to_string(),
        country: resolved.country.clone(),
        source: resolved.source,
        allowed: verdict.is_ok(),
        database: database.to_string(),
        at: now,
    };
    (verdict, record)
}

/// An mmdb country database, and where it came from.
///
/// Deliberately not tied to one vendor: `maxminddb` reads the mmdb *format*, so
/// DB-IP Lite (CC BY 4.0) and sapics/ip-location-db `user-country` (PDDL-1.0,
/// public domain) both work. Both are redistributable inside a node binary,
/// which is the constraint that rules MaxMind's GeoLite2 out — its EULA requires
/// deleting superseded databases within 30 days of a release, and an operator
/// running last month's binary cannot honour that.
pub struct CountryDb {
    reader: maxminddb::Reader<Vec<u8>>,
    /// Provenance recorded on every decision, so a past decision stays
    /// interpretable after the database is updated underneath it.
    label: String,
}

impl CountryDb {
    /// Open an mmdb file. `label` should identify the source and its build date
    /// (e.g. `dbip-country-lite-2026-08`), because it is what a later audit has
    /// to reason from.
    pub fn open(path: &std::path::Path, label: impl Into<String>) -> Result<Self, String> {
        let reader = maxminddb::Reader::open_readfile(path)
            .map_err(|e| format!("could not open country database at {}: {e}", path.display()))?;
        Ok(Self {
            reader,
            label: label.into(),
        })
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    /// ISO 3166-1 alpha-2 for `ip`, or `None` if the database has no answer.
    ///
    /// A miss is not an error: address space is reallocated constantly and no
    /// database is complete. The caller decides what an unknown means, and for
    /// a licence restriction that decision is to refuse.
    pub fn country_of(&self, ip: IpAddr) -> Option<String> {
        let ip = normalize_for_lookup(ip);
        // `decode_path` reads just this field rather than deserialising the
        // whole record — and `country.iso_code` is the one path every mmdb
        // country database shares, so a single reader works across DB-IP,
        // IPinfo and ip-location-db without a vendor-specific type.
        let result = self.reader.lookup(ip).ok()?;
        let code: Option<String> = result
            .decode_path(&maxminddb::path!["country", "iso_code"])
            .ok()?;
        code.map(|c| c.to_ascii_uppercase())
    }
}

/// Whether this node enforces territorial licence restrictions.
///
/// Optional because most models carry no territorial term — seven of the eight
/// custom licences in the catalog are unrestricted — and an operator who serves
/// none of the restricted ones should not need a geo database at all.
///
/// ⚠ The two ways to "turn it off" are not equivalent, which is why this is an
/// enum rather than a bool:
///
/// * [`Self::Enforce`] is the default. Restricted models are checked; every
///   other model is untouched and never sees a geo lookup.
/// * [`Self::RefuseRestricted`] needs no database and no geolocation: the node
///   simply does not serve territorially-restricted models. For an operator who
///   does not want them, this is the honest setting — it removes the obligation
///   rather than the enforcement of it.
/// * [`Self::OperatorAssertsCompliance`] serves restricted models with **no
///   per-request check**. The operator is asserting they satisfy the licence by
///   other means. It exists because that can be legitimate — a private
///   deployment inside the Applicable Territory has no excluded callers to
///   exclude — but it is never inferred, and it is never the default: a node
///   that silently stopped checking would serve outside its grant while
///   appearing to comply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EnforcementMode {
    /// Check restricted models per request. The default.
    #[default]
    Enforce,
    /// Do not serve territorially-restricted models at all.
    RefuseRestricted,
    /// Serve them unchecked; the operator asserts compliance by other means.
    OperatorAssertsCompliance,
}

/// Everything the node needs to decide a territorial question.
///
/// Held as one value so the "no database" case is representable rather than
/// implicit: `db: None` means restricted models refuse, and unrestricted models
/// are untouched.
#[derive(Default)]
pub struct TerritoryEnforcer {
    /// What this node does about territorially-restricted models.
    pub mode: EnforcementMode,
    pub db: Option<CountryDb>,
    /// Reverse proxies whose `X-Forwarded-For` this node will read.
    pub trusted_proxies: Vec<IpAddr>,
    /// What to do about callers on this machine or its private network.
    pub local_policy: LocalCallerPolicy,
    /// Country the operator declares for local callers under
    /// [`LocalCallerPolicy::DeclareInside`].
    pub declared_local_country: Option<String>,
}

impl TerritoryEnforcer {
    /// Resolve the caller's territory from a direct HTTP request.
    pub fn resolve_http(
        &self,
        forwarded_for: Option<&str>,
        socket_addr: Option<IpAddr>,
    ) -> ResolvedTerritory {
        let Some(ip) = client_ip_for_enforcement(forwarded_for, socket_addr, &self.trusted_proxies)
        else {
            return ResolvedTerritory {
                country: None,
                source: TerritorySource::Unknown,
            };
        };

        if is_local(ip) {
            return match (self.local_policy, &self.declared_local_country) {
                (LocalCallerPolicy::DeclareInside, Some(c)) => ResolvedTerritory {
                    country: Some(c.to_ascii_uppercase()),
                    source: TerritorySource::OperatorDeclared,
                },
                // Declaring "inside" without saying where is not a declaration,
                // so it does not resolve. Refusing is the safe reading.
                _ => ResolvedTerritory {
                    country: None,
                    source: TerritorySource::Unknown,
                },
            };
        }

        match self.db.as_ref().and_then(|db| db.country_of(ip)) {
            Some(country) => ResolvedTerritory {
                country: Some(country),
                source: TerritorySource::IpGeo,
            },
            None => ResolvedTerritory {
                country: None,
                source: TerritorySource::IpGeo,
            },
        }
    }

    /// Resolve from a peer-relayed claim.
    ///
    /// ⚠ The serving node never sees the end user, so this can only be as
    /// honest as the peer. Verifying a signature would prove *who* asserted the
    /// country, never that the assertion is true — the value is attribution
    /// after the fact, not prevention.
    ///
    /// No signed-claim scheme is wired yet, so this exists to keep the relay
    /// path explicit rather than silently unguarded: with no claim it resolves
    /// to unknown, and an unknown refuses. A node therefore does not relay
    /// restricted models today, which is the conservative default the design
    /// calls for.
    pub fn resolve_peer(&self, claimed_country: Option<&str>) -> ResolvedTerritory {
        match claimed_country {
            Some(c) if !c.trim().is_empty() => ResolvedTerritory {
                country: Some(c.trim().to_ascii_uppercase()),
                source: TerritorySource::PeerAsserted,
            },
            _ => ResolvedTerritory {
                country: None,
                source: TerritorySource::PeerAsserted,
            },
        }
    }

    /// The label recorded on a decision, including the no-database case.
    pub fn database_label(&self) -> &str {
        self.db.as_ref().map_or("none", |db| db.label())
    }
}

/// Decide whether `model_id` may be served to this caller.
///
/// Returns `Ok(None)` when the model carries no per-request territorial
/// restriction — the overwhelmingly common case, and the one that must stay
/// free of geo lookups entirely.
///
/// 🔑 Scoped to the model on purpose. A node with no geo database loses its
/// restricted models and keeps everything else; a global failure would make the
/// control too expensive to run and would reward deleting the database.
pub fn check_request(
    enforcer: &TerritoryEnforcer,
    model_id: &str,
    license_id: Option<&str>,
    grant: Option<&TerritorialGrant>,
    resolved: &ResolvedTerritory,
    now: u64,
) -> Result<Option<TerritoryDecision>, (TerritoryRefusal, TerritoryDecision)> {
    let (Some(license_id), Some(grant)) = (license_id, grant) else {
        return Ok(None);
    };
    if !grant.is_per_request() {
        return Ok(None);
    }
    match enforcer.mode {
        EnforcementMode::Enforce => {}
        // No database, no geolocation, no request served. The obligation is
        // removed rather than unenforced.
        EnforcementMode::RefuseRestricted => {
            let (_, record) = decide(
                model_id,
                license_id,
                grant,
                &ResolvedTerritory {
                    country: None,
                    source: TerritorySource::Unknown,
                },
                enforcer.database_label(),
                now,
            );
            return Err((
                TerritoryRefusal::Unresolved {
                    reason: "this node does not serve territorially-restricted models",
                },
                record,
            ));
        }
        // Recorded as an operator declaration so the audit trail shows a
        // decision was taken, not that a check silently did not run.
        EnforcementMode::OperatorAssertsCompliance => {
            return Ok(Some(TerritoryDecision {
                model_id: model_id.to_string(),
                license_id: license_id.to_string(),
                country: None,
                source: TerritorySource::OperatorDeclared,
                allowed: true,
                database: enforcer.database_label().to_string(),
                at: now,
            }));
        }
    }
    let (verdict, record) = decide(
        model_id,
        license_id,
        grant,
        resolved,
        enforcer.database_label(),
        now,
    );
    match verdict {
        Ok(()) => Ok(Some(record)),
        Err(refusal) => Err((refusal, record)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use tenzro_types::model::TerritorialScope;

    fn h3_grant() -> TerritorialGrant {
        TerritorialGrant {
            excluded: vec!["EU".into(), "GB".into(), "KR".into(), "US".into()],
            scope: TerritorialScope::WeightsAndOutputs,
        }
    }

    fn v4(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// The bloc token has to expand, or every EU member but the token itself
    /// would be served.
    #[test]
    fn the_eu_token_expands_to_member_states() {
        let g = h3_grant();
        assert!(g.excludes("DE"), "Germany is in the EU");
        assert!(g.excludes("fr"), "matching is case-insensitive");
        assert!(g.excludes("GB"), "the UK is listed separately, post-Brexit");
        assert!(g.excludes("KR"));
        assert!(g.excludes("US"));
        assert!(!g.excludes("CH"), "Switzerland is not in the EU");
        assert!(!g.excludes("JP"));
    }

    /// Only a grant reaching outputs forces a per-request check. A weights-only
    /// restriction is discharged at registration, and checking it per request
    /// would refuse callers the licence never excluded.
    #[test]
    fn only_output_scope_forces_a_per_request_check() {
        assert!(h3_grant().is_per_request());

        let weights_only = TerritorialGrant {
            excluded: vec!["EU".into()],
            scope: TerritorialScope::Weights,
        };
        assert!(!weights_only.is_per_request());
        assert!(weights_only.is_restricted());

        let unrestricted = TerritorialGrant::default();
        assert!(!unrestricted.is_per_request());
        assert!(!unrestricted.is_restricted());
        assert!(!unrestricted.excludes("US"));
    }

    /// ⛔ The regression that would silently void the whole control: trusting
    /// the leftmost X-Forwarded-For entry, which any client can set.
    #[test]
    fn a_spoofed_forwarded_for_cannot_choose_the_country() {
        let proxy = v4("10.0.0.1");
        let trusted = vec![proxy];

        // The client claims to be in Japan; the proxy reports the real address.
        let ip =
            client_ip_for_enforcement(Some("203.0.113.9, 198.51.100.7"), Some(proxy), &trusted);
        assert_eq!(
            ip,
            Some(v4("198.51.100.7")),
            "must take the rightmost untrusted hop, not the client-supplied one"
        );
    }

    /// With no configured proxy, nothing in the header is trustworthy.
    #[test]
    fn without_trusted_proxies_the_header_is_ignored() {
        let ip = client_ip_for_enforcement(Some("203.0.113.9"), Some(v4("198.51.100.7")), &[]);
        assert_eq!(ip, Some(v4("198.51.100.7")));
    }

    /// A peer that is not a trusted proxy cannot have its header believed
    /// either — otherwise any direct caller forges its own location.
    #[test]
    fn an_untrusted_peer_header_is_ignored() {
        let trusted = vec![v4("10.0.0.1")];
        let ip = client_ip_for_enforcement(Some("203.0.113.9"), Some(v4("198.51.100.7")), &trusted);
        assert_eq!(ip, Some(v4("198.51.100.7")));
    }

    /// Chained proxies: walk past every hop we operate.
    #[test]
    fn the_walk_skips_every_trusted_hop() {
        let trusted = vec![v4("10.0.0.1"), v4("10.0.0.2")];
        let ip = client_ip_for_enforcement(
            Some("203.0.113.9, 198.51.100.7, 10.0.0.2"),
            Some(v4("10.0.0.1")),
            &trusted,
        );
        assert_eq!(ip, Some(v4("198.51.100.7")));
    }

    /// IPv4-mapped IPv6 must resolve like its IPv4 form, or the mapped spelling
    /// is a bypass.
    #[test]
    fn ipv4_mapped_ipv6_is_unmapped() {
        let mapped = IpAddr::V6("::ffff:198.51.100.7".parse::<Ipv6Addr>().unwrap());
        assert_eq!(
            normalize_for_lookup(mapped),
            IpAddr::V4("198.51.100.7".parse::<Ipv4Addr>().unwrap())
        );
        assert!(is_local(IpAddr::V6(
            "::ffff:10.0.0.1".parse::<Ipv6Addr>().unwrap()
        )));
    }

    #[test]
    fn local_addresses_are_recognised() {
        assert!(is_local(v4("127.0.0.1")));
        assert!(is_local(v4("10.1.2.3")));
        assert!(is_local(v4("192.168.1.1")));
        assert!(is_local("::1".parse().unwrap()));
        assert!(is_local("fd00::1".parse().unwrap()), "unique-local");
        assert!(is_local("fe80::1".parse().unwrap()), "link-local");
        assert!(!is_local(v4("198.51.100.7")));
    }

    #[test]
    fn an_excluded_country_is_refused_and_recorded() {
        let (verdict, record) = decide(
            "minimax-h3",
            "minimax-h3-community",
            &h3_grant(),
            &ResolvedTerritory {
                country: Some("DE".into()),
                source: TerritorySource::IpGeo,
            },
            "test-db",
            1_700_000_000,
        );
        assert_eq!(
            verdict,
            Err(TerritoryRefusal::Excluded {
                country: "DE".into()
            })
        );
        assert!(!record.allowed);
        assert_eq!(record.country.as_deref(), Some("DE"));
        assert_eq!(record.license_id, "minimax-h3-community");
    }

    #[test]
    fn an_included_country_is_served() {
        let (verdict, record) = decide(
            "minimax-h3",
            "minimax-h3-community",
            &h3_grant(),
            &ResolvedTerritory {
                country: Some("SG".into()),
                source: TerritorySource::IpGeo,
            },
            "test-db",
            1_700_000_000,
        );
        assert!(verdict.is_ok());
        assert!(record.allowed);
    }

    /// Fail closed. An unresolvable caller cannot be shown to be inside the
    /// grant, and for a licence restriction the cost of wrongly serving is not
    /// symmetric with the cost of wrongly refusing.
    #[test]
    fn an_unresolved_territory_fails_closed() {
        for source in [
            TerritorySource::Unknown,
            TerritorySource::IpGeo,
            TerritorySource::PeerAsserted,
        ] {
            let (verdict, record) = decide(
                "minimax-h3",
                "minimax-h3-community",
                &h3_grant(),
                &ResolvedTerritory {
                    country: None,
                    source,
                },
                "test-db",
                1_700_000_000,
            );
            assert!(matches!(verdict, Err(TerritoryRefusal::Unresolved { .. })));
            assert!(!record.allowed);
        }
    }

    /// An unrestricted model must never touch the geo path — most models are
    /// unrestricted and a lookup per request would be pure cost.
    #[test]
    fn an_unrestricted_model_is_not_checked() {
        let e = TerritoryEnforcer::default();
        let resolved = ResolvedTerritory {
            country: None,
            source: TerritorySource::Unknown,
        };
        // No licence at all.
        assert!(matches!(
            check_request(&e, "qwen3.8-flash-next", None, None, &resolved, 0),
            Ok(None)
        ));
        // A licence with no territorial term.
        let unrestricted = TerritorialGrant::default();
        assert!(matches!(
            check_request(
                &e,
                "gemma-3",
                Some("gemma"),
                Some(&unrestricted),
                &resolved,
                0
            ),
            Ok(None)
        ));
    }

    /// A weights-only restriction is discharged at registration. Checking it
    /// per request would refuse callers the licence never excluded — the
    /// over-blocking failure the Llama structure warns about.
    #[test]
    fn a_weights_only_grant_is_not_checked_per_request() {
        let e = TerritoryEnforcer::default();
        let weights_only = TerritorialGrant {
            excluded: vec!["EU".into()],
            scope: TerritorialScope::Weights,
        };
        let resolved = ResolvedTerritory {
            country: Some("DE".into()),
            source: TerritorySource::IpGeo,
        };
        assert!(
            matches!(
                check_request(&e, "m", Some("l"), Some(&weights_only), &resolved, 0),
                Ok(None)
            ),
            "an EU caller is fine when the grant does not reach outputs"
        );
    }

    /// With no database loaded, a restricted model refuses — and says so with
    /// the database recorded as "none", so an audit can tell a missing database
    /// from a genuine miss.
    #[test]
    fn no_database_refuses_only_the_restricted_model() {
        let e = TerritoryEnforcer::default();
        assert_eq!(e.database_label(), "none");

        let resolved = e.resolve_http(None, Some(v4("198.51.100.7")));
        assert!(resolved.country.is_none());

        let err = check_request(
            &e,
            "minimax-h3",
            Some("minimax-h3-community"),
            Some(&h3_grant()),
            &resolved,
            0,
        )
        .expect_err("must refuse without a database");
        assert_eq!(err.1.database, "none");
        assert!(!err.1.allowed);

        // The same node still serves an unrestricted model.
        assert!(matches!(
            check_request(&e, "qwen3.8-flash-next", None, None, &resolved, 0),
            Ok(None)
        ));
    }

    /// A local caller refuses unless the operator declares a territory — and
    /// declaring "inside" without naming where is not a declaration.
    #[test]
    fn a_local_caller_needs_an_explicit_declaration() {
        let refuse = TerritoryEnforcer::default();
        assert!(
            refuse
                .resolve_http(None, Some(v4("127.0.0.1")))
                .country
                .is_none()
        );

        let incomplete = TerritoryEnforcer {
            local_policy: LocalCallerPolicy::DeclareInside,
            declared_local_country: None,
            ..Default::default()
        };
        assert!(
            incomplete
                .resolve_http(None, Some(v4("10.0.0.5")))
                .country
                .is_none(),
            "DeclareInside without a country does not resolve"
        );

        let declared = TerritoryEnforcer {
            local_policy: LocalCallerPolicy::DeclareInside,
            declared_local_country: Some("sg".into()),
            ..Default::default()
        };
        let r = declared.resolve_http(None, Some(v4("192.168.1.10")));
        assert_eq!(r.country.as_deref(), Some("SG"));
        assert_eq!(r.source, TerritorySource::OperatorDeclared);
    }

    /// A relayed request with no claim resolves to unknown, so restricted
    /// models are not served over the relay path today. That is the intended
    /// conservative default, not an oversight.
    #[test]
    fn a_relayed_request_without_a_claim_is_refused() {
        let e = TerritoryEnforcer::default();
        let resolved = e.resolve_peer(None);
        assert_eq!(resolved.source, TerritorySource::PeerAsserted);
        assert!(resolved.country.is_none());

        assert!(
            check_request(
                &e,
                "minimax-h3",
                Some("minimax-h3-community"),
                Some(&h3_grant()),
                &resolved,
                0,
            )
            .is_err()
        );

        // A claim is honoured but recorded as peer-asserted, never as measured.
        let claimed = e.resolve_peer(Some("sg"));
        assert_eq!(claimed.country.as_deref(), Some("SG"));
        assert_eq!(claimed.source, TerritorySource::PeerAsserted);
    }

    /// Enforcement is optional, but the default must be to enforce: a node
    /// that quietly stopped checking would serve outside its grant while
    /// appearing to comply.
    #[test]
    fn enforcement_is_on_by_default() {
        assert_eq!(EnforcementMode::default(), EnforcementMode::Enforce);
        assert_eq!(TerritoryEnforcer::default().mode, EnforcementMode::Enforce);
    }

    /// An operator who wants no part of restricted models refuses them outright
    /// — no database and no geolocation needed.
    #[test]
    fn refuse_restricted_needs_no_database() {
        let e = TerritoryEnforcer {
            mode: EnforcementMode::RefuseRestricted,
            ..Default::default()
        };
        // Even a caller plainly inside the grant is refused: the node is not
        // declining this caller, it is declining the model.
        let inside = ResolvedTerritory {
            country: Some("SG".into()),
            source: TerritorySource::IpGeo,
        };
        let err = check_request(
            &e,
            "minimax-h3",
            Some("minimax-h3-community"),
            Some(&h3_grant()),
            &inside,
            0,
        )
        .expect_err("restricted models are not served in this mode");
        assert!(err.0.message("minimax-h3").contains("does not serve"));
        assert!(!err.1.allowed);

        // Unrestricted models are unaffected.
        assert!(matches!(
            check_request(&e, "qwen3.8-flash-next", None, None, &inside, 0),
            Ok(None)
        ));
    }

    /// The operator can assert compliance by other means — legitimate for a
    /// private deployment inside the territory — but the assertion is recorded
    /// so an audit sees a decision rather than a missing check.
    #[test]
    fn operator_asserted_compliance_is_recorded_not_silent() {
        let e = TerritoryEnforcer {
            mode: EnforcementMode::OperatorAssertsCompliance,
            ..Default::default()
        };
        // Would be refused under Enforce: unresolvable caller.
        let unresolved = ResolvedTerritory {
            country: None,
            source: TerritorySource::Unknown,
        };
        let record = check_request(
            &e,
            "minimax-h3",
            Some("minimax-h3-community"),
            Some(&h3_grant()),
            &unresolved,
            42,
        )
        .expect("served under the operator's assertion")
        .expect("a decision is still recorded");
        assert!(record.allowed);
        assert_eq!(record.source, TerritorySource::OperatorDeclared);
        assert_eq!(record.license_id, "minimax-h3-community");
    }

    /// The refusal has to say what happened; a bare failure produces bug
    /// reports rather than an understood restriction.
    #[test]
    fn a_refusal_explains_itself() {
        let excluded = TerritoryRefusal::Excluded {
            country: "US".into(),
        };
        let msg = excluded.message("minimax-h3");
        assert!(msg.contains("minimax-h3") && msg.contains("US"));

        let unresolved = TerritoryRefusal::Unresolved {
            reason: "no location could be determined",
        };
        assert!(
            unresolved
                .message("minimax-h3")
                .contains("could not establish")
        );
    }
}
