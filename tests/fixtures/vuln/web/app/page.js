export default function Page({ html }) {
  const key = process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY;
  return <div data-k={key} dangerouslySetInnerHTML={{ __html: html }} />;
}
