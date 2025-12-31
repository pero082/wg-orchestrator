import React, { useState, useEffect } from 'react'
import { Shield, Users, Lock, AlertTriangle, Key, CheckCircle, FileText, Zap } from 'lucide-react'

export function Login({ onLogin, error }) {
    const [username, setUsername] = useState('')
    const [password, setPassword] = useState('')
    const [showTempCreds, setShowTempCreds] = useState(false)

    // Check if we should show temp credentials (within 24 hours of first visit)
    useEffect(() => {
        const firstVisit = localStorage.getItem('samnet_first_visit')
        const hasLoggedIn = localStorage.getItem('samnet_logged_in')
        const now = Date.now()

        if (hasLoggedIn) {
            // User has logged in before, don't show temp creds
            setShowTempCreds(false)
        } else if (!firstVisit) {
            // First visit, record timestamp and show creds
            localStorage.setItem('samnet_first_visit', now.toString())
            setShowTempCreds(true)
        } else {
            // Check if within 24 hours
            const elapsed = now - parseInt(firstVisit)
            const twentyFourHours = 24 * 60 * 60 * 1000
            setShowTempCreds(elapsed < twentyFourHours)
        }
    }, [])

    const handleSubmit = (e) => {
        e.preventDefault()
        // Mark as logged in to hide temp creds on future visits
        localStorage.setItem('samnet_logged_in', 'true')
        onLogin(username, password)
    }

    // Only show social auth if running on secure domain (not IP/LAN)
    const isSecureDomain = window.location.protocol === 'https:' &&
        !/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(window.location.hostname) &&
        !window.location.hostname.endsWith('.local') &&
        !window.location.hostname.endsWith('.lan') &&
        window.location.hostname !== 'localhost';

    return (
        <div className="login-container">
            <div className="login-logo text-accent">
                <pre className="login-ascii" style={{ opacity: 0.15 }}>{`
   ███████╗ ██████╗ ███╗   ███╗███╗   ██╗███████╗████████╗
   ██╔════╝██╔══██╗████╗ ████║████╗  ██║██╔════╝╚══██╔══╝
   ███████╗███████║██╔████╔██║██╔██╗ ██║█████╗     ██║   
   ╚════██║██╔══██║██║╚██╔╝██║██║╚██╗██║██╔══╝     ██║   
   ███████║██║  ██║██║ ╚═╝ ██║██║ ╚████║███████╗   ██║   
   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═══╝╚══════╝   ╚═╝   
                    `}</pre>
            </div>

            <div className="login-box animate-scale-in glass shimmer">
                <div className="flex flex-col items-center gap-3 mb-8">
                    <div className="p-4 rounded-2xl bg-accent-cyan-dim border border-accent-cyan/20 animate-glow relative group">
                        <Shield size={40} className="text-accent-cyan relative z-10" />
                        <div className="absolute inset-0 bg-accent-cyan/20 blur-xl rounded-full opacity-0 group-hover:opacity-100 transition-opacity duration-500"></div>
                    </div>
                    <div className="text-center">
                        <h1 className="text-3xl font-extrabold tracking-tighter text-white">
                            SAMNET<span className="text-accent-cyan">WG</span>
                        </h1>
                        <div className="flex items-center justify-center gap-2 mt-1 opacity-70">
                            <Zap size={10} className="text-accent-amber" fill="currentColor" />
                            <p className="text-[10px] text-muted font-mono tracking-[0.3em] uppercase">SecOps Access Control</p>
                            <Zap size={10} className="text-accent-amber" fill="currentColor" />
                        </div>
                    </div>
                </div>

                <form onSubmit={handleSubmit} className="w-full">
                    <div className="space-y-5">
                        <div className="group">
                            <label className="input-label mb-1.5 block text-xs font-semibold text-muted uppercase tracking-wider group-focus-within:text-accent-cyan transition-colors">
                                Operator ID
                            </label>
                            <div className="relative">
                                <input
                                    className="input pl-10 transition-all focus:ring-1 focus:ring-accent-cyan bg-bg-base/50 focus:bg-bg-base group-hover:border-border-strong"
                                    value={username}
                                    onChange={e => setUsername(e.target.value)}
                                    placeholder="Enter identifier..."
                                    autoFocus
                                />
                                <Users size={16} className="absolute left-3 top-3 text-muted pointer-events-none group-focus-within:text-accent-cyan transition-colors" />
                            </div>
                        </div>
                        <div className="group">
                            <label className="input-label mb-1.5 block text-xs font-semibold text-muted uppercase tracking-wider group-focus-within:text-accent-cyan transition-colors">
                                Security Token
                            </label>
                            <div className="relative">
                                <input
                                    type="password"
                                    className="input pl-10 transition-all focus:ring-1 focus:ring-accent-cyan bg-bg-base/50 focus:bg-bg-base group-hover:border-border-strong"
                                    value={password}
                                    onChange={e => setPassword(e.target.value)}
                                    placeholder="••••••••"
                                />
                                <Lock size={16} className="absolute left-3 top-3 text-muted pointer-events-none group-focus-within:text-accent-cyan transition-colors" />
                            </div>
                        </div>
                    </div>

                    {error && (
                        <div className="mt-5 p-3 bg-status-fail-dim border border-status-fail/30 rounded-md flex items-center gap-3 text-status-fail text-xs font-semibold animate-shake">
                            <AlertTriangle size={16} fill="currentColor" className="text-status-fail/20" />
                            <span className="flex-1">{error}</span>
                        </div>
                    )}

                    <button
                        type="submit"
                        className="btn btn-primary w-full mt-8 py-3 font-bold tracking-wide shadow-lg shadow-accent-cyan/10 hover:shadow-accent-cyan/30 transition-all active:scale-[0.98] relative overflow-hidden group"
                    >
                        <span className="relative z-10 flex items-center justify-center gap-2">
                            <Lock size={14} className="group-hover:hidden" />
                            <Lock size={14} className="hidden group-hover:block text-bg-base" open />
                            AUTHENTICATE
                        </span>
                        <div className="absolute inset-0 bg-white/20 translate-x-[-100%] group-hover:translate-x-[100%] transition-transform duration-500 skew-x-[-20deg]"></div>
                    </button>
                </form>

                {/* Default Credentials - Only shown for first 24 hours */}
                {showTempCreds && (
                    <div className="mt-8 border-t border-border-subtle pt-6">
                        <div className="p-3 rounded-lg bg-bg-surface border border-border-default group hover:border-accent-cyan/30 transition-all">
                            <div className="flex items-center justify-between mb-2">
                                <div className="flex items-center gap-2">
                                    <div className="p-1 rounded bg-accent-cyan-dim">
                                        <Key size={12} className="text-accent-cyan" />
                                    </div>
                                    <span className="text-[10px] font-bold text-muted group-hover:text-accent-cyan transition-colors uppercase tracking-wider">Initial Access (24h)</span>
                                </div>
                            </div>

                            <div className="grid grid-cols-2 gap-2">
                                <CredentialItem label="User" value="admin" />
                                <CredentialItem label="Pass" value="changeme" />
                            </div>
                        </div>
                    </div>
                )}

                {isSecureDomain && (
                    <div className="w-full mt-8 animate-fade-in">
                        <div className="relative mb-6">
                            <div className="absolute inset-0 flex items-center">
                                <div className="w-full border-t border-border-subtle"></div>
                            </div>
                            <div className="relative flex justify-center text-xs">
                                <span className="px-3 text-muted bg-panel uppercase tracking-widest font-semibold text-[9px]">SSO Provider</span>
                            </div>
                        </div>
                        <div className="grid grid-cols-2 gap-3">
                            <a href="/api/v1/oauth/google" className="btn btn-secondary flex items-center justify-center gap-2 hover:bg-bg-hover transition-all text-xs h-9">
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
                                    <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4" />
                                    <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853" />
                                    <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05" />
                                    <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335" />
                                </svg>
                                Google
                            </a>
                            <a href="/api/v1/oauth/github" className="btn btn-secondary flex items-center justify-center gap-2 hover:bg-bg-hover transition-all text-xs h-9">
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
                                    <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z" />
                                </svg>
                                GitHub
                            </a>
                        </div>
                    </div>
                )}
            </div>

            <div className="mt-8 text-center text-[10px] text-muted/30 font-mono tracking-widest uppercase">
                <span className="hover:text-accent-cyan transition-colors cursor-pointer">System Secure</span>
                <span className="mx-3">•</span>
                <span>Encrypted</span>
            </div>
        </div>
    )
}

function CredentialItem({ label, value }) {
    const [copied, setCopied] = useState(false)

    const handleCopy = () => {
        navigator.clipboard.writeText(value)
        setCopied(true)
        setTimeout(() => setCopied(false), 2000)
    }

    return (
        <div className="flex justify-between items-center bg-bg-base/50 p-1.5 rounded border border-transparent hover:border-accent-cyan/20 cursor-pointer transition-all" onClick={handleCopy}>
            <span className="text-[9px] font-bold text-muted uppercase pl-1">{label}</span>
            <div className="flex items-center gap-1.5">
                <span className="font-mono text-[10px] text-accent-cyan/90">{value}</span>
                <div className={`transition-all duration-300 ${copied ? 'text-status-ok' : 'text-muted/50'}`}>
                    {copied ? <CheckCircle size={10} /> : <FileText size={10} />}
                </div>
            </div>
        </div>
    )
}
