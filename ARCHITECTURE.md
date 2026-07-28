# Architecture

Diagrams render natively on GitHub. Four views, because one diagram covering
all of this would be unreadable: what exists, what a request passes through,
how it gets built, and how it changes safely.

---

## 1. Components and trust boundaries

The important structural fact is that **MariaDB has no route to the
internet and no host port**. It sits on a Podman `--internal` network, so a
compromised WordPress cannot reach past it and the database is not exposed
even if a firewall rule is wrong.

```mermaid
graph TB
    subgraph HOST["Proxmox VE host"]
        INST["install.sh<br/>lib/00 to 07"]
        NBD["qemu-nbd<br/>direct disk injection"]
        INST --> NBD
    end

    NBD -.->|"writes payload/ onto the disk<br/>before first boot"| VM

    subgraph VM["Alpine VM"]
        NFT["nftables<br/>Layer 1 packet filter"]

        subgraph FRONT["wp-front  10.89.10.0/24<br/>egress + published :80"]
            WP["WordPress<br/>Apache 2.4 + PHP 8.3<br/>cap-drop ALL + 6 caps"]
        end

        subgraph DBNET["wp-db  10.89.20.0/24<br/>--internal : NO egress, NO host port"]
            DB["MariaDB 11.4<br/>cap-drop ALL + 5 caps"]
        end

        CS["CrowdSec<br/>--network host, --read-only<br/>detection engine"]
        BOUNCER["cs-firewall-bouncer"]

        NFT --> WP
        WP <-->|"3306, internal only"| DB
        WP -->|"logs"| CS
        CS --> BOUNCER
        BOUNCER -->|"writes ban rules"| NFT
    end

    INTERNET(["Internet"]) -->|":80 / :443 via proxy"| NFT
    WP -->|"updates, plugin API, SMTP"| INTERNET
    DB -.->|"no path exists"| INTERNET

    style DB fill:#1f2937,stroke:#ef4444,color:#fff
    style DBNET fill:#111827,stroke:#ef4444,color:#fff
    style NFT fill:#1f2937,stroke:#22c55e,color:#fff
    style CS fill:#1f2937,stroke:#22c55e,color:#fff
    style INTERNET fill:#374151,stroke:#9ca3af,color:#fff
```

---

## 2. What a request passes through

Each layer is cheaper than the one after it. A packet dropped at nftables
costs nothing; a request that reaches PHP has already cost a WordPress
bootstrap and a database query. That ordering is the whole point — it is why
brute-force protection escalates from the application layer down to the
firewall rather than living only in PHP.

```mermaid
flowchart TD
    REQ(["Incoming request"]) --> L1{"nftables<br/>Layer 1 — packet"}
    L1 -->|"source not in SSH/Web CIDR"| D1["dropped<br/>zero cost"]
    L1 -->|"IP is CrowdSec-banned"| D2["dropped<br/>zero cost"]
    L1 --> RIP["mod_remoteip<br/>restore real client IP<br/>from trusted proxy only"]

    RIP --> L2A{"8G firewall<br/>.htaccess"}
    L2A -->|"scanner UA, bad pattern"| D3["403"]
    L2A --> L2B{"GeoIP<br/>optional"}
    L2B -->|"country not allowed"| D4["403"]
    L2B --> L2C{"wp-admin<br/>IP restriction"}
    L2C -->|"admin path, IP not allowed"| D5["403"]

    L2C --> PHP["PHP + WordPress bootstrap<br/>first real cost"]
    PHP --> L4{"Login Guard<br/>mu-plugin"}
    L4 -->|"address locked out"| D6["rejected<br/>before password check"]
    L4 --> APP(["WordPress serves the request"])

    L4 -.->|"logs every outcome"| CSX["CrowdSec"]
    CSX -.->|"5 failures in 20s window"| BAN["ban at nftables"]
    BAN -.->|"next request never reaches PHP"| L1

    style D1 fill:#1f2937,stroke:#22c55e,color:#fff
    style D2 fill:#1f2937,stroke:#22c55e,color:#fff
    style BAN fill:#1f2937,stroke:#ef4444,color:#fff
    style PHP fill:#374151,stroke:#f59e0b,color:#fff
    style APP fill:#1f2937,stroke:#22c55e,color:#fff
```

---

## 3. Install flow

Two phases, split by a reboot: the kernel switch has to happen before
containers exist.

```mermaid
flowchart LR
    subgraph P0["Proxmox host"]
        A["install.sh"] --> B["prompts<br/>lib/01"]
        B --> C["fetch Alpine<br/>verify SHA-512"]
        C --> D["build nftables +<br/>Apache config<br/>lib/03"]
        D --> E["mount disk<br/>qemu-nbd"]
        E --> F["inject payload/<br/>+ vars.sh"]
        F --> G["qm create + start"]
    end

    G --> H

    subgraph P1["VM — stage 1"]
        H["expand rootfs<br/>apk upgrade"] --> I["switch to linux-lts"]
        I --> J(["reboot"])
    end

    J --> K

    subgraph P2["VM — stage 2 : stages 01-10"]
        K["health checks<br/>kernel + Podman"] --> L["digest-pin images<br/>Skopeo"]
        L --> M["networks + secrets"]
        M --> N["Apache hardening<br/>8G, slug, CSP"]
        N --> O["MariaDB then WordPress<br/>then GeoIP"]
        O --> P["OpenRC services"]
        P --> Q["update + mail +<br/>plugin tooling"]
        Q --> R["CrowdSec + backups"]
        R --> S["Trivy, Lynis,<br/>malware scanner"]
        S --> T(["validate: ~45 checks"])
    end

    style J fill:#374151,stroke:#f59e0b,color:#fff
    style T fill:#1f2937,stroke:#22c55e,color:#fff
```

---

## 4. Update: candidate, cutover, rollback

Production keeps serving throughout the risky part. The old container is not
destroyed until the new one has proven itself — it *is* the rollback artifact.

```mermaid
flowchart TD
    START(["update.sh wp 6.9.4-php8.4-apache"]) --> CHK{"tag exists?<br/>Skopeo"}
    CHK -->|"no"| STOP1["stop — nothing pulled"]
    CHK --> SCAN{"Trivy scan<br/>HIGH/CRITICAL"}
    SCAN -->|"scan incomplete<br/>+ profile=production"| STOP2["refuse<br/>unknown security state"]
    SCAN --> CAND["start candidate<br/>127.0.0.1:18080<br/>production still on :80"]

    CAND --> VAL{"candidate healthy?<br/>HTTP + PHP + DNS + DB"}
    VAL -->|"no"| STOP3["remove candidate<br/>production never touched"]

    VAL -->|"yes"| REN["rename wordpress to wordpress-old<br/>start new as wordpress"]
    REN --> VAL2{"production healthy?"}

    VAL2 -->|"no"| RB["remove new<br/>rename wordpress-old back<br/>start it"]
    RB --> DONE2(["rolled back<br/>original image restored"])

    VAL2 -->|"yes"| RM["remove wordpress-old"]
    RM --> GEO{"GeoIP was active?"}
    GEO -->|"yes"| REBUILD["rebuild GeoIP layer<br/>on the new base"]
    GEO -->|"no"| DONE1
    REBUILD --> DONE1(["updated"])

    style STOP1 fill:#1f2937,stroke:#f59e0b,color:#fff
    style STOP2 fill:#1f2937,stroke:#f59e0b,color:#fff
    style STOP3 fill:#1f2937,stroke:#f59e0b,color:#fff
    style RB fill:#1f2937,stroke:#ef4444,color:#fff
    style DONE1 fill:#1f2937,stroke:#22c55e,color:#fff
    style DONE2 fill:#1f2937,stroke:#22c55e,color:#fff
```

---

## 5. Day-2 tooling

Each tool covers a layer the others do not. The split matters: `update.sh`
and Trivy see the **container image**, while plugins and themes live in a
mounted volume that an image update never touches — which is where roughly
91% of WordPress vulnerabilities are.

```mermaid
graph LR
    T(["VM tooling"])

    T --> U["update.sh"]
    U --> U1["candidate + cutover + rollback"]
    U --> U2["Trivy CVE scan before applying"]
    U --> U3["digest re-pin + version discovery"]

    T --> V["validate-wordpress.sh"]
    V --> V1["~45 checks, each with a fix command"]
    V --> V2["sections: containers, database, web,<br/>security, updates, logs, backups, mail"]

    T --> P["wp-plugins.sh"]
    P --> P1["update visibility"]
    P --> P2["vulnerability scan<br/>Wordfence bulk feed, matched locally"]
    P --> P3["opt-in: Patchstack, WPScan, NVD"]

    T --> M["wp-malware-scan.sh"]
    M --> M1["PHP in uploads — highest signal"]
    M --> M2["core vs pinned image"]
    M --> M3["YARA rules, tiered"]
    M --> M4["database analysis"]

    T --> H["wp-hardening.sh"]
    H --> H1["feature toggles"]
    H --> H2["egress allow / deny"]
    H --> H3["CrowdSec whitelist"]
    H --> H4["geoip-test"]

    T --> E["wp-mail.sh"]
    E --> E1["status, test, setup, doctor, log"]

    T --> B["wp-db-backup.sh"]
    B --> B1["verified dump before rotation"]

    style T fill:#1f2937,stroke:#22c55e,color:#fff
    style M1 fill:#1f2937,stroke:#22c55e,color:#fff
    style P2 fill:#1f2937,stroke:#22c55e,color:#fff
```

---

*Diagrams describe the system as built. If one disagrees with the code, the
code is right and the diagram is a bug — please report it.*

— **RothITguy**
