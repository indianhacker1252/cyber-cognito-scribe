import { SidebarProvider, SidebarTrigger } from "@/components/ui/sidebar";
import { AppSidebar } from "@/components/AppSidebar";
import VaptChatbox from "@/components/VaptChatbox";
import { CreditBadge } from "@/components/CreditBadge";
import { GlobalJobChip } from "@/components/GlobalJobChip";
import { Button } from "@/components/ui/button";
import { LogOut } from "lucide-react";
import { useAuth } from "@/hooks/useAuth";

export function Layout({ children }: { children: React.ReactNode }) {
  const { user, signOut } = useAuth();
  return (
    <SidebarProvider>
      <div className="min-h-screen flex w-full bg-background">
        <AppSidebar />
        <div className="flex-1 flex flex-col">
          <header className="h-12 flex items-center border-b border-border px-4 gap-3">
            <SidebarTrigger className="text-muted-foreground hover:text-primary" />
            <div className="ml-auto flex items-center gap-3">
              <GlobalJobChip />
              <CreditBadge />
              {user && <span className="text-[10px] font-mono text-muted-foreground hidden md:inline">{user.email}</span>}
              <div className="h-2 w-2 rounded-full bg-primary animate-pulse-glow" />
              <span className="text-[10px] font-mono text-muted-foreground uppercase hidden md:inline">Online</span>
              {user && (
                <Button size="sm" variant="ghost" onClick={signOut} className="h-7">
                  <LogOut className="h-3 w-3" />
                </Button>
              )}
            </div>
          </header>
          <main className="flex-1 p-6 overflow-auto">{children}</main>
        </div>
        <VaptChatbox />
      </div>
    </SidebarProvider>
  );
}
