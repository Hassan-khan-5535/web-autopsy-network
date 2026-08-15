import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Web Autopsy Network",
  description: "Evidence-first web intelligence infrastructure.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
