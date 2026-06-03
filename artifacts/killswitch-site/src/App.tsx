import { Switch, Route, Router as WouterRouter } from "wouter";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { HelmetProvider } from "react-helmet-async";
import NotFound from "@/pages/not-found";

import Home from "@/pages/Home";
import Docs from "@/pages/Docs";
import Demo from "@/pages/Demo";
import Features from "@/pages/Features";
import Quickstart from "@/pages/Quickstart";
import WhyKillswitch from "@/pages/WhyKillswitch";

const queryClient = new QueryClient();

function Router() {
  return (
    <Switch>
      <Route path="/" component={Home} />
      <Route path="/demo" component={Demo} />
      <Route path="/docs" component={Docs} />
      <Route path="/features" component={Features} />
      <Route path="/quickstart" component={Quickstart} />
      <Route path="/why-killswitch" component={WhyKillswitch} />
      <Route component={NotFound} />
    </Switch>
  );
}

function App() {
  return (
    <HelmetProvider>
      <QueryClientProvider client={queryClient}>
        <TooltipProvider>
          <WouterRouter base={import.meta.env.BASE_URL.replace(/\/$/, "")}>
            <Router />
          </WouterRouter>
          <Toaster />
        </TooltipProvider>
      </QueryClientProvider>
    </HelmetProvider>
  );
}

export default App;
