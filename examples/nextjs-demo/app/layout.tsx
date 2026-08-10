import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "rsc-sentinel — Server Action guard demo",
  description:
    "Live demo of rsc-sentinel's withActionGuard protecting a real Next.js 16 Server Action.",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en" className="h-full antialiased">
      <body className="min-h-full flex flex-col font-sans">{children}</body>
    </html>
  );
}
