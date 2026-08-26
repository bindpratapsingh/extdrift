"""extdrift — behavioral-diff detection of malicious browser-extension updates.

Package layout
--------------
    engine.unpack    .crx/.xpi unpacking and manifest normalisation
    engine.sandbox   instrumented browser runs that produce traces (Playwright)
    engine.features  trace -> feature vector, and the version delta
    engine.scoring   transparent weighted-rule scorer (the heuristics tier)
    engine.report    human-readable + JSON verdict rendering

The core (unpack/features/scoring/report) is deliberately standard-library only so
it runs on any machine, including the 4 GB laptop.  Only engine.sandbox needs the
heavy third-party stack (Playwright, mitmproxy).
"""

__version__ = "0.1.0"
