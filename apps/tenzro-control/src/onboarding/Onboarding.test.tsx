// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { answers, budget, calls, config, hardware, resetIpc, wallet } from "@/test/ipc";
import { Onboarding } from "./Onboarding";

beforeEach(() => {
  resetIpc();
  answers.scan_hardware = hardware;
  answers.model_budget = budget;
  answers.pricing_brackets = () => [];
  for (const cmd of [
    "set_roles",
    "set_models",
    "set_availability",
    "set_ai_pricing",
    "set_storage_pricing",
    "set_compute_pricing",
    "complete_onboarding",
  ]) {
    answers[cmd] = () => config();
  }
});
afterEach(cleanup);

async function next(label = "Continue") {
  const button = await screen.findByRole("button", { name: label });
  await vi.waitFor(() => expect((button as HTMLButtonElement).disabled).toBe(false));
  fireEvent.click(button);
}

describe("onboarding", () => {
  it("walks every step and saves the choices before the node starts", async () => {
    answers.get_config = () => config({ roles: ["validator"] });
    answers.wallet_status = () => wallet();
    const onDone = vi.fn();
    render(<Onboarding onDone={onDone} />);

    await screen.findByText("What this machine can do");
    await next(); // scan
    await next(); // roles
    await next(); // wallet
    await next(); // availability
    await next(); // pricing
    await screen.findByText("Check it over");
    await next("Start the node");

    await vi.waitFor(() => expect(onDone).toHaveBeenCalledOnce());
    const saved = calls.map((c) => c.cmd).filter((c) => c.startsWith("set_") || c === "complete_onboarding");
    expect(saved).toEqual([
      "set_roles",
      "set_models",
      "set_availability",
      "set_ai_pricing",
      "set_storage_pricing",
      "set_compute_pricing",
      "complete_onboarding",
    ]);
    expect(calls.find((c) => c.cmd === "set_roles")?.args).toEqual({ roles: ["validator"] });
  });

  it("sets up the wallet from the machine's hardware key", async () => {
    answers.get_config = () => config({ roles: ["validator"] });
    answers.wallet_status = () => wallet({ exists: false, custody: "none", address: "", display_address: "" });
    answers.wallet_use_hardware_key = () => wallet();
    render(<Onboarding onDone={() => {}} />);

    await screen.findByText("What this machine can do");
    await next();
    await next();
    const name = await screen.findByPlaceholderText("Studio Mac");
    fireEvent.change(name, { target: { value: "Rack 4" } });
    await next("Create");
    await vi.waitFor(() =>
      expect(calls.find((c) => c.cmd === "wallet_use_hardware_key")?.args).toEqual({ displayName: "Rack 4" }),
    );
    await next(); // the wallet now exists
    await screen.findByRole("button", { name: "Continue" });
  });

  it("keeps the operator on the step when saving fails", async () => {
    answers.get_config = () => config({ roles: ["validator"] });
    answers.wallet_status = () => wallet();
    answers.set_roles = () => {
      throw new Error("the node refused the roles");
    };
    const onDone = vi.fn();
    render(<Onboarding onDone={onDone} />);
    await screen.findByText("What this machine can do");
    for (let i = 0; i < 5; i++) await next();
    await next("Start the node");
    expect(await screen.findByText(/the node refused the roles/)).toBeTruthy();
    expect(onDone).not.toHaveBeenCalled();
    expect(calls.some((c) => c.cmd === "complete_onboarding")).toBe(false);
  });
});
