import { useState } from "react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

const VERDICTS = ["TRUE_POSITIVE", "FALSE_POSITIVE", "EXPECTED_EDGE_CASE"] as const;

type OutcomeModalProps = {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  txId: string;
  onSubmit: (payload: {
    verdict: (typeof VERDICTS)[number];
    impact_usd: number | null;
    reviewer_id: string;
    notes: string;
  }) => Promise<void>;
};

export function OutcomeModal({ open, onOpenChange, txId, onSubmit }: OutcomeModalProps) {
  const [verdict, setVerdict] = useState<(typeof VERDICTS)[number]>("TRUE_POSITIVE");
  const [impactUsd, setImpactUsd] = useState("");
  const [reviewerId, setReviewerId] = useState("");
  const [notes, setNotes] = useState("");
  const [saving, setSaving] = useState(false);

  const submit = async () => {
    setSaving(true);
    try {
      await onSubmit({
        verdict,
        impact_usd: impactUsd ? Number(impactUsd) : null,
        reviewer_id: reviewerId,
        notes,
      });
      onOpenChange(false);
      setImpactUsd("");
      setReviewerId("");
      setNotes("");
      setVerdict("TRUE_POSITIVE");
    } finally {
      setSaving(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Submit Review Outcome</DialogTitle>
          <DialogDescription>Transaction: {txId}</DialogDescription>
        </DialogHeader>
        <div className="space-y-3">
          <Select value={verdict} onValueChange={(value) => setVerdict(value as (typeof VERDICTS)[number])}>
            <SelectTrigger>
              <SelectValue placeholder="Verdict" />
            </SelectTrigger>
            <SelectContent>
              {VERDICTS.map((item) => (
                <SelectItem key={item} value={item}>
                  {item}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>

          <Input
            type="number"
            placeholder="Impact USD"
            value={impactUsd}
            onChange={(e) => setImpactUsd(e.target.value)}
          />

          <Input
            placeholder="Reviewer ID"
            value={reviewerId}
            onChange={(e) => setReviewerId(e.target.value)}
          />

          <Textarea
            placeholder="Notes"
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
          />
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={!reviewerId || saving}>
            {saving ? "Submitting..." : "Submit"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
