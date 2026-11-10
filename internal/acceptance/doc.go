// Package acceptance holds the end-to-end checks for a milestone: they build the
// real binaries and drive them the way a user and an agent would, rather than
// calling internal packages. They are the executable form of the milestone's
// exit criterion (SRS §10), the adversarial scenarios (§11.3) and the
// non-functional constraints that can be tested without a reference node
// (NFR-4.5, NFR-5.1, NFR-5.4, RK-8).
package acceptance
