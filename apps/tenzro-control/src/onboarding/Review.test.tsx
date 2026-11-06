// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { answers, budget, calls, gate, resetIpc, wallet } from "@/test/ipc";
import { Review } from "./Review";

const pricing = {
  inputWei: "0",
  outputWei: "0",
  storageMinWei: "0",
  storageMaxWei: "0",
  computeHourWei: "0",
};

function show(roles: string[], handlers: { onDropRole?: (r: string) => void; onFinish?: () => void } = {}) {
  render(
    <Review
      roles={roles}
      models={[]}
      storagePledgeGb={0}
      availability={{ always_on: false, windows: [{ start_hour: 9, end_hour: 17, days: [0, 1] }] }}
      pricing={pricing}
      onDropRole={handlers.onDropRole ?? (() => {})}
      onBack={() => {}}
      onFinish={handlers.onFinish ?? (() => {})}
    />,
  );
}

beforeEach(() => {
  resetIpc();
  answers.model_budget = budget;
});
afterEach(cleanup);

describe("review screen", () => {
  it("shows the hardware wallet and the serving hours", async () => {
    answers.wallet_status = () => wallet();
    show(["validator"]);
    expect(await screen.findByText("Hardware key")).toBeTruthy();
    expect(screen.getByText("0xabab...abab")).toBeTruthy();
    expect(screen.getByText("Mon, Tue")).toBeTruthy();
    expect(calls.map((c) => c.cmd).sort()).toEqual(["model_budget", "wallet_status"]);
  });

  it("names an unfunded role and lets the operator drop it", async () => {
    answers.wallet_status = () =>
      wallet({
        gates: [gate("validator", { label: "Validator", can_stake: false, shortfall_display: "1,000 TNZO" })],
      });
    const onDropRole = vi.fn();
    show(["validator"], { onDropRole });
    expect(await screen.findByText("Stake shortfall")).toBeTruthy();
    expect(screen.getByText("1,000 TNZO short of 1,000 TNZO")).toBeTruthy();
    fireEvent.click(screen.getByText("Drop role"));
    expect(onDropRole).toHaveBeenCalledWith("validator");
  });

  it("shows a validator the exact bond step and where to send TNZO", async () => {
    answers.wallet_status = () =>
      wallet({
        stake_account: { address: `0x${"cd".repeat(32)}`, signer: "tpm" },
        gates: [gate("validator", { label: "Validator", can_stake: false, required_display: "10,000 TNZO", shortfall_display: "10,000 TNZO" })],
      });
    show(["validator"]);
    expect(await screen.findByText("Validator registration")).toBeTruthy();
    expect(screen.getByText(`0x${"cd".repeat(32)}`)).toBeTruthy();
    expect(screen.getByText("Self-stake")).toBeTruthy();
  });

  it("starts the node from the last step", async () => {
    answers.wallet_status = () => wallet();
    const onFinish = vi.fn();
    show(["validator"], { onFinish });
    await screen.findByText("Hardware key");
    expect(screen.queryByText("Stake shortfall")).toBeNull();
    fireEvent.click(screen.getByText("Start the node"));
    expect(onFinish).toHaveBeenCalledOnce();
  });
});
