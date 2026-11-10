"""
QLoRA fine-tuning of Qwen2.5-Coder-3B-Instruct on CVEfixes security-fix pairs.

Hardware target: RTX 4050 Laptop GPU (6 GB VRAM), Windows 11
Model: Qwen/Qwen2.5-Coder-3B-Instruct  (~1.75 GB VRAM in 4-bit)
Data:  benchmarks/results/training_pairs.jsonl  (423 pairs)

Usage
-----
  uv run python -m benchmarks.training_data.train_qlora
  uv run python -m benchmarks.training_data.train_qlora --epochs 3 --output models/sentinel-coder

Options
-------
  --data PATH      JSONL file (default: benchmarks/results/training_pairs.jsonl)
  --model ID       HuggingFace model ID (default: Qwen/Qwen2.5-Coder-3B-Instruct)
  --output DIR     where to save the LoRA adapter (default: models/sentinel-coder)
  --epochs N       training epochs (default: 2)
  --max-seq N      max token length per sample (default: 512)
  --batch N        per-device batch size (default: 1)
  --grad-accum N   gradient accumulation steps (default: 8)
  --lora-r N       LoRA rank (default: 16)
  --lora-alpha N   LoRA alpha (default: 32)
  --lr FLOAT       learning rate (default: 2e-4)
  --dry-run        check setup only, do not train
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_jsonl(path: Path) -> list[dict]:
    records = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def _apply_chat_template(tokenizer, messages: list[dict]) -> str:
    """Format messages list into a single training string using the model's chat template."""
    return tokenizer.apply_chat_template(
        messages,
        tokenize=False,
        add_generation_prompt=False,
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="QLoRA fine-tune Qwen2.5-Coder on CVEfixes pairs")
    parser.add_argument("--data",       type=Path, default=Path("benchmarks/results/training_pairs.jsonl"))
    parser.add_argument("--model",      default="Qwen/Qwen2.5-Coder-3B-Instruct")
    parser.add_argument("--output",     type=Path, default=Path("models/sentinel-coder"))
    parser.add_argument("--epochs",     type=int,   default=2)
    parser.add_argument("--max-seq",    type=int,   default=512)
    parser.add_argument("--batch",      type=int,   default=1)
    parser.add_argument("--grad-accum", type=int,   default=8)
    parser.add_argument("--lora-r",     type=int,   default=16)
    parser.add_argument("--lora-alpha", type=int,   default=32)
    parser.add_argument("--lr",         type=float, default=2e-4)
    parser.add_argument("--dry-run",    action="store_true")
    args = parser.parse_args()

    # --- Import check ---
    try:
        import torch
    except ImportError:
        print("ERROR: torch not installed. Run: uv pip install torch --index-url https://download.pytorch.org/whl/cu126")
        sys.exit(1)

    try:
        from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig, TrainingArguments
        from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training, TaskType
        from trl import SFTTrainer, SFTConfig
        from datasets import Dataset
    except ImportError as e:
        print(f"ERROR: missing training dependency: {e}")
        print("Run: uv pip install transformers peft trl bitsandbytes accelerate datasets")
        sys.exit(1)

    # --- GPU check ---
    if not torch.cuda.is_available():
        print("WARNING: CUDA not available — training on CPU (will be very slow)")
    else:
        gpu = torch.cuda.get_device_properties(0)
        vram_gb = gpu.total_memory / 1024**3
        print(f"GPU: {gpu.name}  VRAM: {vram_gb:.1f} GB")
        if vram_gb < 4:
            print("ERROR: need at least 4 GB VRAM for 3B model in 4-bit")
            sys.exit(1)
        # TF32 matmul: ~2x faster on Ampere+ for bf16/fp32 operations
        torch.set_float32_matmul_precision("high")
        torch.backends.cuda.matmul.allow_tf32 = True
        torch.backends.cudnn.allow_tf32 = True

    # --- Load data ---
    if not args.data.exists():
        print(f"ERROR: data file not found: {args.data}")
        sys.exit(1)

    raw = _load_jsonl(args.data)
    print(f"Loaded {len(raw)} training pairs from {args.data}")

    if args.dry_run:
        print("\nDry-run: setup OK. Use without --dry-run to train.")
        return

    # --- Tokenizer ---
    print(f"\nLoading tokenizer: {args.model}")
    tokenizer = AutoTokenizer.from_pretrained(args.model, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    tokenizer.padding_side = "right"

    # --- Format dataset ---
    texts = []
    for item in raw:
        try:
            text = _apply_chat_template(tokenizer, item["messages"])
            texts.append({"text": text})
        except Exception:
            pass
    print(f"Formatted {len(texts)} examples after chat-template")

    hf_dataset = Dataset.from_list(texts)

    # --- Model in 4-bit ---
    print(f"\nLoading model in 4-bit: {args.model}")
    bnb_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.bfloat16,
        bnb_4bit_use_double_quant=True,
    )
    model = AutoModelForCausalLM.from_pretrained(
        args.model,
        quantization_config=bnb_config,
        device_map="auto",
        trust_remote_code=True,
    )
    model = prepare_model_for_kbit_training(model, use_gradient_checkpointing=True)

    # --- LoRA ---
    lora_config = LoraConfig(
        task_type=TaskType.CAUSAL_LM,
        r=args.lora_r,
        lora_alpha=args.lora_alpha,
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
        lora_dropout=0.05,
        bias="none",
    )
    model = get_peft_model(model, lora_config)
    model.print_trainable_parameters()

    # --- Training args ---
    args.output.mkdir(parents=True, exist_ok=True)

    training_args = SFTConfig(
        output_dir=str(args.output),
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch,
        gradient_accumulation_steps=args.grad_accum,
        learning_rate=args.lr,
        fp16=False,
        bf16=torch.cuda.is_available(),
        logging_steps=25,
        save_steps=250,
        save_total_limit=2,
        warmup_steps=20,
        lr_scheduler_type="cosine",
        optim="paged_adamw_8bit",
        gradient_checkpointing=True,
        gradient_checkpointing_kwargs={"use_reentrant": False},
        max_length=args.max_seq,
        dataset_text_field="text",
        # packing: fills each 768-token window with multiple short examples instead of padding
        packing=True,
        report_to="none",
    )

    # --- Train ---
    trainer = SFTTrainer(
        model=model,
        args=training_args,
        train_dataset=hf_dataset,
        processing_class=tokenizer,
    )

    print(f"\nStarting training: {args.epochs} epoch(s), batch={args.batch}, grad_accum={args.grad_accum}")
    print(f"Effective batch size: {args.batch * args.grad_accum}")
    print(f"Output: {args.output}\n")

    trainer.train()
    trainer.save_model(str(args.output))
    tokenizer.save_pretrained(str(args.output))

    print(f"\nTraining complete. LoRA adapter saved to: {args.output}")
    print("To merge and push: use peft merge_adapter or load with PeftModel.from_pretrained()")


if __name__ == "__main__":
    main()
