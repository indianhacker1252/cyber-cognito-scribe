import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { Layout } from "@/components/Layout";
import { AuthProvider } from "@/hooks/useAuth";
import { ProtectedRoute } from "@/components/ProtectedRoute";
import Index from "./pages/Index";
import Auth from "./pages/Auth";
import AdminPanel from "./pages/AdminPanel";
import Targets from "./pages/Targets";
import NeuralLog from "./pages/NeuralLog";
import Findings from "./pages/Findings";
import Approvals from "./pages/Approvals";
import SystemHealth from "./pages/SystemHealth";
import IntelFeed from "./pages/IntelFeed";
import Settings from "./pages/Settings";
import FalsePositives from "./pages/FalsePositives";
import AttackVisualization from "./pages/AttackVisualization";
import MythosResults from "./pages/MythosResults";
import AppPackages from "./pages/AppPackages";
import OwaspCoverage from "./pages/OwaspCoverage";
import KillChains from "./pages/KillChains";
import NotFound from "./pages/NotFound";

const queryClient = new QueryClient();

const App = () => (
  <QueryClientProvider client={queryClient}>
    <TooltipProvider>
      <Toaster />
      <Sonner />
      <BrowserRouter>
        <AuthProvider>
          <Routes>
            <Route path="/auth" element={<Auth />} />
            <Route path="/*" element={
              <ProtectedRoute>
                <Layout>
                  <Routes>
                    <Route path="/" element={<Index />} />
                    <Route path="/targets" element={<Targets />} />
                    <Route path="/logs" element={<NeuralLog />} />
                    <Route path="/findings" element={<Findings />} />
                    <Route path="/approvals" element={<Approvals />} />
                    <Route path="/system-health" element={<SystemHealth />} />
                    <Route path="/intel-feed" element={<IntelFeed />} />
                    <Route path="/settings" element={<Settings />} />
                    <Route path="/admin" element={<AdminPanel />} />
                    <Route path="/false-positives" element={<FalsePositives />} />
                    <Route path="/attack-viz" element={<AttackVisualization />} />
                    <Route path="/mythos" element={<MythosResults />} />
                    <Route path="/app-packages" element={<AppPackages />} />
                    <Route path="/coverage" element={<OwaspCoverage />} />
                    <Route path="/kill-chains" element={<KillChains />} />
                    <Route path="*" element={<NotFound />} />
                  </Routes>
                </Layout>
              </ProtectedRoute>
            } />
          </Routes>
        </AuthProvider>
      </BrowserRouter>
    </TooltipProvider>
  </QueryClientProvider>
);

export default App;
