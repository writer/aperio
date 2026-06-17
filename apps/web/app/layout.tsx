import type { Metadata } from "next";
import { Space_Grotesk, JetBrains_Mono } from "next/font/google";
import { AuthShell } from "../components/auth/auth-shell";
import { ThemeProvider } from "../components/layout/theme-provider";
import "./globals.css";

const display = Space_Grotesk({
  subsets: ["latin"],
  display: "swap",
  variable: "--font-display",
  weight: ["400", "500", "600", "700"]
});

const mono = JetBrains_Mono({
  subsets: ["latin"],
  display: "swap",
  variable: "--font-mono",
  weight: ["400", "500", "600"]
});

export const metadata: Metadata = {
  title: "Aperio",
  description: "SaaS Detection & Response on Cerebro"
};

const themeBootstrap = `
(function(){try{var p=localStorage.getItem('aperio.theme')||'dark';var t=p==='system'?(matchMedia('(prefers-color-scheme: light)').matches?'light':'dark'):p;var r=document.documentElement;if(t==='dark'){r.classList.add('dark');}r.style.colorScheme=t;}catch(e){}})();
`;

export default function RootLayout({
  children
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: themeBootstrap }} />
      </head>
      <body
        className={`${display.variable} ${mono.variable} min-h-screen bg-background font-sans text-foreground`}
      >
        <ThemeProvider>
          <AuthShell>{children}</AuthShell>
        </ThemeProvider>
      </body>
    </html>
  );
}
