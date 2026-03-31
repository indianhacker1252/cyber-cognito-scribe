import { LayoutDashboard, Crosshair, Terminal, ShieldAlert, ClipboardCheck, Activity, Rss } from "lucide-react";
import { NavLink } from "@/components/NavLink";
import { useLocation } from "react-router-dom";
import {
  Sidebar,
  SidebarContent,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarHeader,
  useSidebar,
} from "@/components/ui/sidebar";

const navItems = [
  { title: "Command Center", url: "/", icon: LayoutDashboard },
  { title: "Targets", url: "/targets", icon: Crosshair },
  { title: "Neural Log", url: "/logs", icon: Terminal },
  { title: "Findings", url: "/findings", icon: ShieldAlert },
  { title: "Approvals", url: "/approvals", icon: ClipboardCheck },
  { title: "System Health", url: "/system-health", icon: Activity },
  { title: "Intel Feed", url: "/intel-feed", icon: Rss },
];

export function AppSidebar() {
  const { state } = useSidebar();
  const collapsed = state === "collapsed";
  const location = useLocation();

  return (
    <Sidebar collapsible="icon" className="border-r border-border">
      <SidebarHeader className="p-4">
        <div className="flex items-center gap-2">
          <div className="h-8 w-8 rounded-md bg-primary/20 border border-primary/40 flex items-center justify-center glow-green">
            <Crosshair className="h-4 w-4 text-primary" />
          </div>
          {!collapsed && (
            <div>
              <h1 className="text-sm font-bold text-primary font-mono text-glow-green">CYBERSCOPE</h1>
              <p className="text-[10px] text-muted-foreground font-mono">SCANNER v1.0</p>
            </div>
          )}
        </div>
      </SidebarHeader>
      <SidebarContent>
        <SidebarGroup>
          <SidebarGroupLabel className="text-muted-foreground font-mono text-[10px] uppercase tracking-widest">
            {!collapsed && "Operations"}
          </SidebarGroupLabel>
          <SidebarGroupContent>
            <SidebarMenu>
              {navItems.map((item) => (
                <SidebarMenuItem key={item.title}>
                  <SidebarMenuButton asChild>
                    <NavLink
                      to={item.url}
                      end={item.url === "/"}
                      className="hover:bg-primary/10 transition-colors"
                      activeClassName="bg-primary/15 text-primary border-l-2 border-primary"
                    >
                      <item.icon className="h-4 w-4 mr-2" />
                      {!collapsed && <span className="font-mono text-xs">{item.title}</span>}
                    </NavLink>
                  </SidebarMenuButton>
                </SidebarMenuItem>
              ))}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>
      </SidebarContent>
    </Sidebar>
  );
}
