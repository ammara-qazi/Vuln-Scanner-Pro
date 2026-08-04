import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Route, Switch, Router as WouterRouter } from 'wouter';
import Home from './pages/home';

const queryClient = new QueryClient();

function NotFound() {
  return (
    <div className="min-h-screen w-full flex items-center justify-center bg-background text-foreground font-mono p-4">
      <div className="border border-destructive p-8 max-w-md text-center bg-card shadow-2xl glow-critical">
        <h1 className="text-6xl font-bold text-destructive mb-4">404</h1>
        <p className="text-xl mb-6 uppercase tracking-wider text-muted-foreground">Directory not found</p>
        <div className="text-sm text-left bg-[#050805] p-4 border border-border mb-6">
          <span className="text-destructive">ERR</span>: The requested path does not exist on this server.<br/>
          <span className="text-primary">ACT</span>: Return to root directory.
        </div>
        <a href="/" className="inline-block px-6 py-2 border border-primary text-primary hover:bg-primary hover:text-primary-foreground transition-colors uppercase">
          &gt; cd /
        </a>
      </div>
    </div>
  );
}

function Router() {
  return (
    <Switch>
      <Route path="/" component={Home} />
      <Route component={NotFound} />
    </Switch>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <WouterRouter base={import.meta.env.BASE_URL.replace(/\/$/, '')}>
        <Router />
      </WouterRouter>
    </QueryClientProvider>
  );
}

export default App;
