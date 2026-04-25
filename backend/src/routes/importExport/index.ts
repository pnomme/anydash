import { registerAnyDashImportRoutes } from "./anydashImportRoutes";
import { registerAnyDashExportRoute } from "./exportRoutes";
import { registerLegacySqliteImportRoutes } from "./legacySqliteImportRoutes";
import { RegisterImportExportDeps } from "./shared";

export const registerImportExportRoutes = (deps: RegisterImportExportDeps) => {
  registerAnyDashExportRoute(deps);
  registerAnyDashImportRoutes(deps);
  registerLegacySqliteImportRoutes(deps);
};

export type { RegisterImportExportDeps } from "./shared";
