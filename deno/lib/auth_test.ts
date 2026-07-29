import { assertEquals, assert } from "jsr:@std/assert@1";
import { generate, verify, currentWindow } from "./auth.ts";

const TEST_SECRET = "0123456789abcdef0123456789abcdef";

Deno.test("golden register", async () => {
  const token = await generate(TEST_SECRET, "register", 1000000);
  assertEquals(token.length, 32);
  assertEquals(token, "6cb2fbc4a51a0132a2909d6110251362");
});

Deno.test("golden discover", async () => {
  const token = await generate(TEST_SECRET, "discover", 1000000);
  assertEquals(token, "210a9b69b8ffce133e9d2d96c63262b0");
});

Deno.test("golden gate", async () => {
  const token = await generate(TEST_SECRET, "gate", 1000000);
  assertEquals(token, "0a5b30e06bfa21db06f164a4c3535665");
});

Deno.test("verify exact window", async () => {
  const token = await generate(TEST_SECRET, "gate", 5000);
  assert(await verify(TEST_SECRET, "gate", token, 5000));
});

Deno.test("verify tolerance +1", async () => {
  const token = await generate(TEST_SECRET, "gate", 4999);
  assert(await verify(TEST_SECRET, "gate", token, 5000));
});

Deno.test("verify tolerance -1", async () => {
  const token = await generate(TEST_SECRET, "gate", 5001);
  assert(await verify(TEST_SECRET, "gate", token, 5000));
});

Deno.test("verify outside tolerance", async () => {
  const token = await generate(TEST_SECRET, "gate", 4998);
  assert(!await verify(TEST_SECRET, "gate", token, 5000));
});

Deno.test("purpose mismatch", async () => {
  const token = await generate(TEST_SECRET, "register", 5000);
  assert(!await verify(TEST_SECRET, "discover", token, 5000));
});

Deno.test("wrong secret", async () => {
  const token = await generate("wrong-secret-32-bytes-long!!!!!", "gate", 5000);
  assert(!await verify(TEST_SECRET, "gate", token, 5000));
});

Deno.test("rejects short token", async () => {
  assert(!await verify(TEST_SECRET, "gate", "too-short", 5000));
});

Deno.test("currentWindow returns positive", () => {
  assert(currentWindow() > 0);
});
