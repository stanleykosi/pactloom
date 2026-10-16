import { Children, cloneElement, isValidElement, useEffect, useId, useRef, type ReactNode, type ReactElement } from 'react';
import { formatZec } from '@wholepact/sdk';
export function Icon({ name, size = 20 }: { name: string; size?: number }) {
  const paths: Record<string, ReactNode> = {
    overview: <><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></>,
    agreements: <><path d="M7 3h10l3 3v15H4V3zM8 8h8M8 12h8M8 16h5"/></>,
    authorizations: <><path d="m12 3 8 3v6c0 5-8 9-8 9s-8-4-8-9V6zM8 12l3 3 5-6"/></>,
    accounts: <><path d="M8 8 5 5a4 4 0 0 0-4 4l4 4M16 16l3 3a4 4 0 0 0 4-4l-4-4M7 17 17 7M5 15l4 4M15 5l4 4"/></>,
    records: <><path d="M5 3h14v18l-3-2-4 2-4-2-3 2zM8 8h8M8 12h8"/></>,
    settings: <><circle cx="12" cy="12" r="3"/><path d="m9 3-1 3-3 1-2 3 2 2-1 4 3 2 3-1 2 4 3-1 1-3 4-1 1-3-3-2 1-3-3-3-3 1z"/></>,
    plus: <path d="M12 5v14M5 12h14"/>, arrow: <path d="M5 12h14m-6-6 6 6-6 6"/>,
    back: <path d="M19 12H5m6-6-6 6 6 6"/>, close: <path d="m6 6 12 12M18 6 6 18"/>,
    lock: <><rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3M12 14v3"/></>,
    info: <><circle cx="12" cy="12" r="9"/><path d="M12 11v6M12 7v1"/></>,
    refresh: <><path d="M20 7v5h-5M4 17v-5h5M6 7a7 7 0 0 1 12-1l2 3M4 15l2 3a7 7 0 0 0 12-1"/></>,
    check: <path d="m5 12 4 4L19 6"/>, warning: <><path d="m12 3 10 18H2zM12 9v5M12 17v1"/></>,
    key: <><circle cx="8" cy="8" r="5"/><path d="m12 12 9 9M16 16l3-3M19 19l3-3"/></>,
    clock: <><circle cx="12" cy="12" r="9"/><path d="M12 6v6l4 2"/></>,
  };
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{paths[name] ?? paths.info}</svg>;
}
export function Mark({ large = false }: { large?: boolean }) { return <span className={`mark ${large ? 'large' : ''}`} aria-hidden="true"><span/><span/></span>; }
export function Badge({ children, tone = 'neutral' }: { children: ReactNode; tone?: 'neutral' | 'warning' | 'plain' }) { return <span className={`badge ${tone}`}><span className="badge-dot"/>{children}</span>; }
export function Money({ value, detail = false }: { value: string; detail?: boolean }) { return <span className="money" title={`${value} zatoshis`}>{formatZec(value, detail)} <span>ZEC</span></span>; }
export function Notice({ title, children, warning = false }: { title?: string; children: ReactNode; warning?: boolean }) { return <div className={`notice ${warning ? 'warning' : ''}`}><Icon name={warning ? 'warning' : 'info'}/><div>{title && <strong>{title}</strong>}<div>{children}</div></div></div>; }
export function Empty({ icon = 'agreements', title, children, action }: { icon?: string; title: string; children: ReactNode; action?: ReactNode }) { return <div className="empty"><div className="empty-icon"><Icon name={icon} size={27}/></div><h3>{title}</h3><p>{children}</p>{action}</div>; }
export function PageTitle({ kicker, title, children, action }: { kicker: string; title: string; children?: ReactNode; action?: ReactNode }) { return <div className="page-heading"><div><p className="eyebrow">{kicker}</p><h1>{title}</h1>{children && <p className="subtitle">{children}</p>}</div>{action}</div>; }
export function Modal({ title, children, onClose, wide = false }: { title: string; children: ReactNode; onClose: () => void; wide?: boolean }) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => { const element = ref.current; if (!element) return; const previousFocus = document.activeElement; element.showModal(); return () => { element.close(); if (previousFocus instanceof HTMLElement && previousFocus.isConnected) previousFocus.focus(); }; }, []);
  return <dialog ref={ref} className={`modal ${wide ? 'wide' : ''}`} onCancel={onClose} onKeyDown={event => { if (event.key !== 'Tab') return; const controls = [...event.currentTarget.querySelectorAll<HTMLElement>('button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), summary, [tabindex]:not([tabindex="-1"])')].filter(element => element.getClientRects().length > 0); const first = controls[0]; const last = controls[controls.length - 1]; if (!first || !last) return; if (event.shiftKey && (document.activeElement === first || document.activeElement === event.currentTarget)) { event.preventDefault(); last.focus(); } else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); } }} aria-labelledby="modal-title"><header><div><p className="eyebrow">Local workspace</p><h2 id="modal-title">{title}</h2></div><button className="icon-button" onClick={onClose} aria-label="Close dialog"><Icon name="close"/></button></header>{children}</dialog>;
}
export function Field({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) { const id = useId(); return <label className="field"><span id={`${id}-label`}>{label}</span>{Children.map(children, child => isValidElement(child) && ['input','select','textarea'].includes(String(child.type)) ? cloneElement(child as ReactElement<Record<string,unknown>>, { 'aria-labelledby': `${id}-label`, 'aria-describedby': hint ? `${id}-hint` : undefined }) : child)}{hint && <small id={`${id}-hint`}>{hint}</small>}</label>; }
export function human(value: string) { return value.replace(/_/g, ' ').replace(/^./, c => c.toUpperCase()); }
export function dateTime(value?: string | null) { if (!value) return 'Not set'; const date = new Date(value); return Number.isNaN(date.getTime()) ? value : `${new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short', timeZone: 'UTC' }).format(date)} UTC`; }
