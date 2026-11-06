import { matchesKey, truncateToWidth, isKeyRelease, isKeyRepeat } from "@earendil-works/pi-tui";
import register from "./command.js";

export default function (pi) {
  register(pi, { matchesKey, truncateToWidth, isKeyRelease, isKeyRepeat });
}
