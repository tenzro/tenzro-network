// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { answers, calls, resetIpc, wallet } from "@/test/ipc";
import { Wallet } from "./Wallet";

const to = "0x" + "cd".repeat(20);

beforeEach(() => {
  resetIpc();
  answers.wallet_status = () => wallet({ balance_wei: "5000000000000000000", balance_display: "5 TNZO" });
});
afterEach(cleanup);

async function fill(recipient: string, amount: string) {
  render(<Wallet />);
  fireEvent.change(await screen.findByPlaceholderText("0x…"), { target: { value: recipient } });
  fireEvent.change(screen.getByPlaceholderText("0.0"), { target: { value: amount } });
  return screen.getByRole("button", { name: "Send" }) as HTMLButtonElement;
}

describe("wallet send", () => {
  it("sends the amount in wei to the recipient and shows the receipt", async () => {
    answers.wallet_send = (args) => ({
      custody: "hardware",
      from: "0x" + "ab".repeat(32),
      to: args?.to,
      amount_wei: args?.amountWei,
      amount_display: "1.5",
      reference: "0x" + "11".repeat(32),
    });
    const send = await fill(to, "1.5");
    await vi.waitFor(() => expect(send.disabled).toBe(false));
    fireEvent.click(send);
    await vi.waitFor(() =>
      expect(calls.find((c) => c.cmd === "wallet_send")?.args).toEqual({ to, amountWei: "1500000000000000000" }),
    );
    expect(await screen.findByText("1.5 TNZO")).toBeTruthy();
  });

  it("refuses an address of the wrong width before anything is signed", async () => {
    const send = await fill("0x" + "cd".repeat(19), "1");
    expect(await screen.findByText(/40 or 64 hex characters/)).toBeTruthy();
    expect(send.disabled).toBe(true);
    expect(calls.some((c) => c.cmd === "wallet_send")).toBe(false);
  });
});
