import Lenis from 'lenis';
import { useEffect } from 'react';
import Shield from '../shield/Shield';
import Button from '../ui/Button';
import Icon from '../ui/Icon';
import ThemeToggle from '../ui/ThemeToggle';
import Architecture from './landing/Architecture';
import ScanSteps from './landing/ScanSteps';
import { DETECTS, DOC, NOT_CHECKED, PROBLEMS, REPO_URL } from './landing.content';
import { LANDING_PLATES } from './landing.fixtures';

/** Lenis smooth scroll on the landing page only (never in the app), off for reduced motion. */
function useLenis() {
  useEffect(() => {
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return undefined;
    const lenis = new Lenis({ lerp: 0.12 });
    let raf;
    const loop = (time) => { lenis.raf(time); raf = requestAnimationFrame(loop); };
    raf = requestAnimationFrame(loop);
    return () => { cancelAnimationFrame(raf); lenis.destroy(); };
  }, []);
}

const go = (hash) => () => { window.location.hash = hash; };

export default function Landing({ theme, onThemeChange }) {
  useLenis();

  return (
    <div className="landing">
      <a className="skip-link" href="#landing-main">Skip to content</a>

      <header className="lnav">
        <a className="brand" href="#/">
          <span className="brand-mark" aria-hidden="true" />
          <span className="brand-name">Aegis Node</span>
        </a>
        <nav aria-label="Site">
          <ul className="lnav__links">
            <li><a href="#product">Product</a></li>
            <li><a href="#how">How it works</a></li>
            <li><a href="#research">Research</a></li>
            <li><a href={REPO_URL} rel="noopener noreferrer" target="_blank">GitHub<span className="visually-hidden"> (opens in a new tab)</span></a></li>
          </ul>
        </nav>
        <div className="lnav__actions">
          <ThemeToggle theme={theme} onChange={onThemeChange} />
          <Button variant="primary" onClick={go('/app/scan')}>Scan a dataset</Button>
        </div>
      </header>

      <main id="landing-main">
        <section className="hero" id="product" aria-labelledby="hero-title">
          <div className="hero__halftone" aria-hidden="true" />
          <div className="hero__copy">
            <h1 id="hero-title">Scan datasets for hidden payloads before use</h1>
            <p className="hero__sub">
              Aegis Node reads every cell of a CSV, JSON, Parquet or Excel file, flags formula, script, SQL and
              prompt-injection payloads and embedded malware, and hands back a sanitized copy that has been scanned again.
            </p>
            <div className="hero__ctas">
              <Button variant="primary" onClick={go('/app/scan')}>Scan a dataset</Button>
              <a className="text-link" href={DOC('docs/AEGIS_NODE_SECURITY_ARCHITECTURE.md')} rel="noopener noreferrer" target="_blank">
                Read the threat model<span className="visually-hidden"> (opens in a new tab)</span>
              </a>
            </div>
          </div>
          <div className="hero__visual">
            <Shield datasets={LANDING_PLATES} mode="hero" theme={theme} label="Illustration of the Aegis shield with sample datasets" />
            <p className="hero__note muted">Illustration with sample datasets. In the app, each plate is one of your datasets.</p>
          </div>
        </section>

        <section className="problems" aria-labelledby="problems-title">
          <h2 id="problems-title" className="section-title">Why a dataset needs a security scan</h2>
          <ol className="problems__list">
            {PROBLEMS.map((p) => (
              <li key={p.title}>
                <h3>{p.title}</h3>
                <p>{p.body}</p>
              </li>
            ))}
          </ol>
        </section>

        <section className="how" id="how" aria-labelledby="how-title">
          <div className="how__intro">
            <h2 id="how-title" className="section-title">How a scan works</h2>
            <p className="muted">Five stages run in order on the server. The first four decide the verdict; nothing downstream can overrule them.</p>
          </div>
          <ScanSteps />
        </section>

        <section className="detects" aria-labelledby="detects-title">
          <div className="detects__head">
            <h2 id="detects-title" className="section-title">What it detects</h2>
            <p className="muted">{NOT_CHECKED}</p>
          </div>
          <div className="table-wrap detects__table">
            <table className="table">
              <caption className="visually-hidden">Checks the scanner runs</caption>
              <thead>
                <tr><th scope="col">Area</th><th scope="col">Rules</th><th scope="col">What it catches</th></tr>
              </thead>
              <tbody>
                {DETECTS.map((d) => (
                  <tr key={d.area}>
                    <th scope="row" data-label="Area">{d.area}</th>
                    <td data-label="Rules" className="is-mono">{d.rules}</td>
                    <td data-label="What it catches">{d.what}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        <section className="research" id="research" aria-labelledby="research-title">
          <h2 id="research-title" className="section-title">For examiners and researchers</h2>
          <div className="research__grid">
            <Architecture />
            <div className="research__text">
              <h3>Evaluation method</h3>
              <p>
                The scanner is tested against a labelled benchmark of clean, suspicious and malicious datasets, and the
                prompt-injection guardrail against separate development and holdout sets that were never used for tuning.
                The project reports its limits openly, including the guardrail's holdout result.
              </p>
              <ul className="link-list">
                <li><a href={DOC('docs/RESEARCH_METHODOLOGY.md')} rel="noopener noreferrer" target="_blank">Research methodology</a></li>
                <li><a href={DOC('docs/LIMITATIONS.md')} rel="noopener noreferrer" target="_blank">Known limitations</a></li>
                <li><a href={DOC('docs/AEGIS_NODE_SECURITY_ARCHITECTURE.md')} rel="noopener noreferrer" target="_blank">Security architecture</a></li>
                <li><a href={REPO_URL} rel="noopener noreferrer" target="_blank">Source code</a></li>
              </ul>
            </div>
          </div>
        </section>

        <section className="cta-band" aria-labelledby="cta-title">
          <h2 id="cta-title">Check a dataset before it reaches your pipeline</h2>
          <div className="cta-band__actions">
            <Button variant="primary" onClick={go('/app/scan')}>Scan a dataset</Button>
            <a className="text-link" href={REPO_URL} rel="noopener noreferrer" target="_blank">
              View source on GitHub<span className="visually-hidden"> (opens in a new tab)</span>
            </a>
          </div>
        </section>
      </main>

      <footer className="lfoot">
        <div className="lfoot__cols">
          <div>
            <span className="brand-name">Aegis Node</span>
            <p className="muted">Dataset threat detection and remediation. M.Tech project by Mummuluri Sandeep Sunny, 2026.</p>
          </div>
          <ul className="link-list" aria-label="Project links">
            <li><a href={REPO_URL} rel="noopener noreferrer" target="_blank">GitHub</a></li>
            <li><a href={DOC('README.md')} rel="noopener noreferrer" target="_blank">Documentation</a></li>
            <li><a href={DOC('docs/THESIS_EVIDENCE_PACKAGE.md')} rel="noopener noreferrer" target="_blank">Thesis evidence</a></li>
            <li><a href={DOC('LICENSE')} rel="noopener noreferrer" target="_blank">MIT licence</a></li>
          </ul>
          <ul className="link-list" aria-label="App">
            <li><a href="#/app">Open the app</a></li>
            <li><a href="#/styleguide">Styleguide</a></li>
          </ul>
        </div>
        <p className="lfoot__fine muted">
          <Icon name="ShieldCheck" size={14} /> A research tool. It does not replace an organisation's own security review.
        </p>
      </footer>
    </div>
  );
}
