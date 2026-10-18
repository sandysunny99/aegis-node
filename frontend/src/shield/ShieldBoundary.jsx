import { Component } from 'react';

/**
 * If the 3D chunk fails to load (offline, or a stale page after a redeploy) or WebGL throws,
 * show the 2D plate grid instead of taking the whole page down.
 */
export default class ShieldBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { failed: false };
  }

  static getDerivedStateFromError() {
    return { failed: true };
  }

  render() {
    return this.state.failed ? this.props.fallback : this.props.children;
  }
}
