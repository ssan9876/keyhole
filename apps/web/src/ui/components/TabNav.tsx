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
 * A row of tab buttons. The active tab is expressed by `aria-current="page"`
 * alone -- tokens.css styles it off that attribute, so the accessible state and
 * the visible state cannot drift apart. The strip scrolls horizontally rather
 * than wrapping, which keeps five tabs on one line at 375px.
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
    <nav aria-label="Sections" className="kh-tabs">
      {tabs.map((tab) => {
        const isActive = tab.id === active;
        return (
          <button
            key={tab.id}
            type="button"
            className="kh-tab"
            aria-current={isActive ? "page" : undefined}
            onClick={() => onSelect(tab.id)}
          >
            {tab.label}
          </button>
        );
      })}
    </nav>
  );
}
