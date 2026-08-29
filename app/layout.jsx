import './globals.css'

export const metadata = {
  title: 'Big Bounty — Security Testing Tool',
  description: 'Autonomous security testing and vulnerability scanner',
}

export const viewport = {
  width: 'device-width',
  initialScale: 1,
}

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  )
}
