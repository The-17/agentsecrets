import json

def main():
    transcript_path = "/mnt/c/Users/steppa/.gemini/antigravity/brain/c8645626-159c-4d3f-89d0-907c4886b350/.system_generated/logs/transcript.jsonl"
    keywords = ["macos", "mac-", "tmate", "darwin", "mac "]
    
    with open(transcript_path, "r", encoding="utf-8") as f:
        for line in f:
            try:
                step = json.loads(line.strip())
                if step.get("source") == "USER_EXPLICIT" and step.get("type") == "USER_INPUT":
                    content = step.get("content", "")
                    if any(k in content.lower() for k in keywords):
                        print(f"Step {step.get('step_index')} ({step.get('created_at')}):")
                        print(content)
                        print("-" * 50)
            except Exception as e:
                pass

if __name__ == "__main__":
    main()
