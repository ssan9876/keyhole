export interface TabNavItem<T extends string = string> {
  id: T;
  label: string;
}

export interface TabNavProps<T extends string = string> {
  tabs: TabNavItem<T>[];
  active: T;
  onSelect(id: T): void;
}

/**
 * A row of tab buttons, one style computation shared by every tab.
 *
 * Pulled out of VaultScreen after a role-gated tab (Admin) was special-cased
 * with its own copy of the button style object, right next to the mapped
 * tabs using the same style -- a DRY gap waiting to drift. The caller now
 * folds a role-gated tab into the same array with `.filter()` before handing
 * it to this component, so there is exactly one place that renders a tab
 * button.
 */
export function TabNav<T extends string>({ tabs, active, onSelect }: TabNavProps<T>) {
  return (
    <nav aria-label="Sections" style={{ display: "flex", gap: "var(--space-2)", marginBottom: "var(--space-4)" }}>
      {tabs.map((tab) => {
        const isActive = tab.id === active;
        return (
          <button
            key={tab.id}
            type="button"
            aria-current={isActive ? "page" : undefined}
            onClick={() => onSelect(tab.id)}
            style={{
              font: "inherit",
              background: "transparent",
              border: "none",
              borderBottom: isActive ? "2px solid var(--ink)" : "2px solid transparent",
              color: isActive ? "var(--ink)" : "var(--ink-muted)",
              padding: "var(--space-1) 0",
              cursor: "pointer",
            }}
          >
            {tab.label}
          </button>
        );
      })}
    </nav>
  );
}
