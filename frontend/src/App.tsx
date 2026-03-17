import { Switch, Route, Router as WouterRouter } from "wouter";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import NotFound from "@/pages/not-found";
import Home from "@/pages/Home";
import UnlockPage from "@/pages/dashboard/Unlock";
import ReviewQueuePage from "@/pages/dashboard/ReviewQueue";
import RecommendationsPage from "@/pages/dashboard/Recommendations";
import AgentsPage from "@/pages/dashboard/Agents";
import ThresholdsPage from "@/pages/dashboard/Thresholds";
import RiskAdvisoriesPage from "@/pages/dashboard/RiskAdvisories";
import CryptoInspectorPage from "@/pages/dashboard/CryptoInspector";
import AgentIntentPage from "@/pages/dashboard/AgentIntent";
import ABVariantsPage from "@/pages/dashboard/ABVariants";
import AgentEvolutionPage from "@/pages/dashboard/AgentEvolution";

// TanStack Query configuration
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: false,
    },
  },
});

function Router() {
  return (
    <Switch>
      <Route path="/" component={Home} />
      <Route path="/dashboard" component={UnlockPage} />
      <Route path="/dashboard/review-queue" component={ReviewQueuePage} />
      <Route path="/dashboard/recommendations" component={RecommendationsPage} />
      <Route path="/dashboard/agents" component={AgentsPage} />
      <Route path="/dashboard/thresholds" component={ThresholdsPage} />
      <Route path="/dashboard/risk-advisories" component={RiskAdvisoriesPage} />
      <Route path="/dashboard/crypto" component={CryptoInspectorPage} />
      <Route path="/dashboard/agent-intent" component={AgentIntentPage} />
      <Route path="/dashboard/ab-variants" component={ABVariantsPage} />
      <Route path="/dashboard/agent-evolution" component={AgentEvolutionPage} />
      {/* 404 Catch-all */}
      <Route component={NotFound} />
    </Switch>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <WouterRouter base={import.meta.env.BASE_URL.replace(/\/$/, "")}>
          <Router />
        </WouterRouter>
        <Toaster />
      </TooltipProvider>
    </QueryClientProvider>
  );
}

export default App;
