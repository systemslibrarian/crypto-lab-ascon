/**
 * Exhibit: self-check quiz. Every answer is verifiable by doing something
 * in the demo itself — each explanation points at the exhibit that proves it.
 */

interface QuizQuestion {
  question: string;
  options: string[];
  answer: number;
  explain: string;
  tryIt: string;
}

const QUESTIONS: QuizQuestion[] = [
  {
    question: 'You flip a single bit of the ciphertext, then decrypt. What happens?',
    options: [
      'One byte of the recovered plaintext is corrupted',
      'The whole plaintext comes out garbled',
      'Decryption refuses entirely — the tag no longer verifies',
    ],
    answer: 2,
    explain:
      'AEAD is all-or-nothing: the tag authenticates every bit of ciphertext (and the associated data), so verification fails and you get no plaintext at all.',
    tryIt: 'Prove it: Exhibit 3 → Encrypt, Tamper One Bit, Decrypt.',
  },
  {
    question: 'Which words of the 320-bit state form the capacity — the part that must stay secret?',
    options: ['x0–x1', 'x2–x4', 'All five words', 'Only x4'],
    answer: 1,
    explain:
      'x0–x1 are the rate, where data enters and ciphertext leaves; x2–x4 are the capacity, which never touches the outside world. Security lives in the capacity.',
    tryIt: 'See it: Exhibit 1 labels every word, and ciphertext only ever reads the rate.',
  },
  {
    question: 'Roughly how many rounds does one flipped input bit need to influence about half the state?',
    options: ['1 round', '3–4 rounds', 'All 12 rounds', 'It never reaches half'],
    answer: 1,
    explain:
      'The S-box mixes each bit into its 5-bit column and the linear layer spreads it across words; the difference reaches ~50% density in about 3–4 rounds — the margin beyond that is the safety buffer.',
    tryIt: 'Watch it: Exhibit 2 → Plant the Seed → Step One Round, and read the per-round log.',
  },
  {
    question: 'Two messages are encrypted with the same key AND the same nonce. What leaks?',
    options: [
      'Nothing, as long as the key stays secret',
      'The key itself',
      'The XOR of the plaintexts, through the first block where they differ',
    ],
    answer: 2,
    explain:
      'The keystreams are identical until the messages diverge, so C1⊕C2 = P1⊕P2 through the first differing block — knowing one message reveals the other, no key required.',
    tryIt: 'Break it: Exhibit 4 → Encrypt Both — SAME Nonce.',
  },
  {
    question: 'Why is Ascon’s S-box naturally constant-time?',
    options: [
      'It is computed from AND/XOR/NOT only — no table lookups or secret-dependent branches',
      'It runs in dedicated hardware',
      'It is precomputed and cached at startup',
    ],
    answer: 0,
    explain:
      'Table-based S-boxes (like unaccelerated AES) can leak secrets through cache timing. Ascon’s S-box is a fixed sequence of bitwise operations, so it takes the same time regardless of the data.',
    tryIt: 'Inspect it: Exhibit 1 → S-box microscope — the outputs are computed live from the same gate logic.',
  },
];

export function sectionHtml(num: number): string {
  const items = QUESTIONS.map((q, qi) => {
    const options = q.options
      .map(
        (opt, oi) => `
          <label class="quiz-option">
            <input type="radio" name="quiz-${qi}" value="${oi}" />
            <span>${opt}</span>
          </label>`,
      )
      .join('');
    return `
      <fieldset class="quiz-item" id="quiz-item-${qi}">
        <legend>${qi + 1}. ${q.question}</legend>
        ${options}
        <p class="quiz-feedback" id="quiz-feedback-${qi}"></p>
      </fieldset>`;
  }).join('');

  return `
    <section class="panel" id="exhibit-quiz">
      <h2><span class="ex-num" aria-hidden="true">${num}</span> Check Yourself</h2>
      <p>Five questions. Every answer can be verified by doing, not believing — each explanation points at the exhibit that proves it.</p>
      <form id="quiz-form">
        ${items}
        <div class="controls">
          <button id="quiz-check" type="submit">Check Answers</button>
          <button id="quiz-reset" type="button">Reset</button>
        </div>
        <p id="quiz-score" class="status" role="status" aria-live="polite"></p>
      </form>
    </section>
  `;
}

export function wire(byId: <T extends HTMLElement>(id: string) => T): void {
  const form = byId<HTMLFormElement>('quiz-form');
  const score = byId<HTMLParagraphElement>('quiz-score');

  form.addEventListener('submit', (event) => {
    event.preventDefault();
    let correct = 0;
    let answered = 0;

    QUESTIONS.forEach((q, qi) => {
      const feedback = byId<HTMLParagraphElement>(`quiz-feedback-${qi}`);
      const picked = form.querySelector<HTMLInputElement>(`input[name="quiz-${qi}"]:checked`);
      if (!picked) {
        feedback.textContent = 'Not answered yet.';
        feedback.className = 'quiz-feedback';
        return;
      }
      answered += 1;
      if (Number.parseInt(picked.value, 10) === q.answer) {
        correct += 1;
        feedback.textContent = `✓ Correct. ${q.explain} ${q.tryIt}`;
        feedback.className = 'quiz-feedback good';
      } else {
        feedback.textContent = `✗ Not quite. ${q.explain} ${q.tryIt}`;
        feedback.className = 'quiz-feedback bad';
      }
    });

    score.textContent =
      answered < QUESTIONS.length
        ? `${correct} / ${answered} answered correct — ${QUESTIONS.length - answered} still open.`
        : correct === QUESTIONS.length
          ? `${correct} / ${QUESTIONS.length} — perfect. You didn't memorize it, you watched it happen.`
          : `${correct} / ${QUESTIONS.length} correct — the misses each point at an exhibit worth a second visit.`;
    score.className = correct === answered && answered === QUESTIONS.length ? 'status good' : 'status neutral';
  });

  byId<HTMLButtonElement>('quiz-reset').addEventListener('click', () => {
    form.reset();
    score.textContent = '';
    QUESTIONS.forEach((_, qi) => {
      const feedback = byId<HTMLParagraphElement>(`quiz-feedback-${qi}`);
      feedback.textContent = '';
      feedback.className = 'quiz-feedback';
    });
  });
}
