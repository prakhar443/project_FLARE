# FLARE — Base Papers

**Project:** FLARE — Early Detection of Low-Rate Flow-Table Overflow (LOFT) Attacks in Software-Defined Networks
**Prepared for:** project review
**Purpose:** the foundational literature this work is built on and positioned against.

---

## Primary base papers

These two define the project: one is the **attack** we defend against, the other is the **closest existing defence** we improve on.

### 1. FloRa — the defence we extend  *(lead base paper)*
A. Mudgal, A. Verma, M. Singh, K. S. Sahoo, E. Elmroth, and M. H. Bhuyan,
"FloRa: Flow Table Low-Rate Overflow Reconnaissance and Detection in SDN,"
*IEEE Transactions on Network and Service Management (TNSM)*, 2024.
DOI: 10.1109/TNSM.2024.3446178 · Open preprint: arXiv:2410.19832

**Relevance to FLARE.** FloRa is the most recent and closest published defence against LOFT
attacks. It uses a machine-learning classifier over flow-table features to detect malicious
flows and evict them. FLARE is positioned directly relative to FloRa — we target the same
threat but aim to add a time-to-overflow forecast and a training-free, online detection path.
This is the paper to read in full first; it sets the bar and appears in our target journal.

### 2. The LOFT attack — the threat we address
J. Cao, M. Xu, Q. Li, K. Sun, Y. Yang, and J. Zheng,
"Disrupting SDN via the Data Plane: A Low-Rate Flow Table Overflow Attack,"
*Proc. Int. Conf. on Security and Privacy in Communication Systems (SecureComm)*, 2017, pp. 356–376.

**Relevance to FLARE.** This is the paper that introduced the LOFT attack: quietly filling a
switch's flow table with low-rate flows that are refreshed just before their idle timeout, so
the table overflows using almost no traffic and evades volume-based defences. It defines the
two-phase threat model (reconnaissance → slow installation) that FLARE is designed to detect.

---

## Supporting foundation

Context papers that justify specific parts of the design.

### 3. Flow-table capacity/timeout inference (basis for the "probing" phase)
J. Leng, Y. Zhou, J. Zhang, and C. Hu,
"An Inference Attack Model for Flow Table Capacity and Usage: Exploiting the Vulnerability of
Flow Table Overflow in Software-Defined Network," arXiv:1504.03095, 2015.
*Why it matters:* shows an attacker can remotely infer the idle timeout and table size — the
reconnaissance FLARE tries to detect early.

### 4. Denial-of-service via OpenFlow rule installation
R. Kandoi and M. Antikainen,
"Denial-of-Service Attacks in OpenFlow SDN Networks,"
*IFIP/IEEE Int. Symp. on Integrated Network Management (IM)*, 2015, pp. 1322–1326.
*Why it matters:* establishes flow-table exhaustion as a practical DoS vector in SDN.

### 5. Feasibility of attacking SDN
S. Shin and G. Gu,
"Attacking Software-Defined Networks: A First Feasibility Study,"
*ACM SIGCOMM Workshop on Hot Topics in SDN (HotSDN)*, 2013, pp. 165–166.
*Why it matters:* early demonstration that the SDN control/data-plane interaction is attackable.

### 6. Why the flow table is small and expensive (the root vulnerability)
A. R. Curtis, J. C. Mogul, J. Tourrilhes, P. Yalagandula, P. Sharma, and S. Banerjee,
"DevoFlow: Scaling Flow Management for High-Performance Networks,"
*ACM SIGCOMM*, 2011, pp. 254–265.
*Why it matters:* documents the limited TCAM/flow-table capacity that makes overflow possible.

### 7. Change-detection method behind FLARE's core detector
E. S. Page, "Continuous Inspection Schemes," *Biometrika*, vol. 41, no. 1/2, pp. 100–115, 1954.
*Why it matters:* the CUSUM procedure FLARE uses to detect the slow, persistent table growth.

---

## Notes
- **FloRa (#1) is the direct predecessor** and is published in our intended venue (IEEE TNSM).
  Any comparison and novelty claim must be made carefully against FloRa's actual method, not a
  simplified baseline.
- FloRa's citation (authors, venue, DOI) is verified. For the supporting papers, confirm exact
  page numbers on IEEE Xplore / ACM Digital Library before formal submission.
