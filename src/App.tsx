import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { Layout } from "@/components/Layout";
import Index from "./pages/Index";
import Targets from "./pages/Targets";
import NeuralLog from "./pages/NeuralLog";
import Findings from "./pages/Findings";
import Approvals from "./pages/Approvals";
import SystemHealth from "./pages/SystemHealth";
import IntelFeed from "./pages/IntelFeed";
import NotFound from "./pages/NotFound";

const queryClient = new QueryClient();

const App = () => (
  <QueryClientProvider client={queryClient}>
    <TooltipProvider>
      <Toaster />
      <Sonner />
      <BrowserRouter>
        <Layout>
          <Routes>
            <Route path="/" element={<Index />} />
            <Route path="/targets" element={<Targets />} />
            <Route path="/logs" element={<NeuralLog />} />
            <Route path="/findings" element={<Findings />} />
            <Route path="/approvals" element={<Approvals />} />
            <Route path="/system-health" element={<SystemHealth />} />
            <Route path="/intel-feed" element={<IntelFeed />} />
            <Route path="*" element={<NotFound />} />
          </Routes>
        </Layout>
      </BrowserRouter>
    </TooltipProvider>
  </QueryClientProvider>
);

export default App;
