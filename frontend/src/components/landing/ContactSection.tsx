import { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { useToast } from "@/hooks/use-toast";

// Must strictly match the OpenAPI ContactFormInput definition
const formSchema = z.object({
  name: z.string().min(1, "Name is required"),
  email: z.string().email("Please enter a valid email address"),
  company: z.string().min(1, "Company name is required"),
  message: z.string().min(1, "Message is required"),
});

type FormData = z.infer<typeof formSchema>;

interface ContactSectionProps {
  id: string;
  type: 'demo' | 'sales';
  title: React.ReactNode;
  description: string;
  alignment: 'left' | 'right';
}

export function ContactSection({ id, type, title, description, alignment }: ContactSectionProps) {
  const { toast } = useToast();
  const endpoint = type === "demo"
    ? import.meta.env.VITE_DEMO_FORM_ENDPOINT
    : import.meta.env.VITE_SALES_FORM_ENDPOINT;
  const [isSubmitting, setIsSubmitting] = useState(false);

  const { register, handleSubmit, reset, formState: { errors } } = useForm<FormData>({
    resolver: zodResolver(formSchema),
  });

  const onSubmit = async (data: FormData) => {
    if (!endpoint) {
      toast({
        title: "Missing form endpoint",
        description: "Set VITE_DEMO_FORM_ENDPOINT and VITE_SALES_FORM_ENDPOINT to receive submissions.",
        variant: "destructive",
      });
      return;
    }

    setIsSubmitting(true);
    try {
      const res = await fetch(endpoint, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(data),
      });

      if (!res.ok) {
        throw new Error(`Request failed (${res.status})`);
      }

      toast({
        title: "Request Received",
        description: "Our team will be in touch shortly.",
        className: "border-primary bg-background",
      });
      reset();
    } catch (err) {
      toast({
        title: "Submission Failed",
        description: err instanceof Error ? err.message : "An unexpected error occurred. Please try again.",
        variant: "destructive",
      });
    } finally {
      setIsSubmitting(false);
    }
  };

  const ContentBlock = () => (
    <div className="flex flex-col justify-center space-y-6 lg:max-w-lg">
      <h2 className="text-3xl md:text-5xl font-display font-bold text-foreground">
        {title}
      </h2>
      <p className="text-lg text-muted-foreground leading-relaxed">
        {description}
      </p>
      <div className="flex items-center space-x-4 pt-4 text-sm text-muted-foreground">
        <div className="flex items-center">
          <div className="w-2 h-2 rounded-full bg-primary mr-2" />
          Average response time: 2 hours
        </div>
      </div>
    </div>
  );

  const FormBlock = () => (
    <div className="bg-card/50 backdrop-blur-sm border border-border p-8 rounded-3xl shadow-xl">
      <form onSubmit={handleSubmit(onSubmit)} className="space-y-5">
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-5">
          <div className="space-y-2">
            <label className="text-sm font-medium text-foreground">Full Name</label>
            <Input 
              {...register("name")} 
              placeholder="Satoshi Nakamoto"
              className="bg-background/50 border-border h-12 focus-visible:ring-primary/50"
            />
            {errors.name && <p className="text-xs text-destructive">{errors.name.message}</p>}
          </div>
          <div className="space-y-2">
            <label className="text-sm font-medium text-foreground">Work Email</label>
            <Input 
              {...register("email")} 
              placeholder="satoshi@bitcoin.org" 
              type="email"
              className="bg-background/50 border-border h-12 focus-visible:ring-primary/50"
            />
            {errors.email && <p className="text-xs text-destructive">{errors.email.message}</p>}
          </div>
        </div>

        <div className="space-y-2">
          <label className="text-sm font-medium text-foreground">Company</label>
          <Input 
            {...register("company")} 
            placeholder="Bitcoin Foundation"
            className="bg-background/50 border-border h-12 focus-visible:ring-primary/50"
          />
          {errors.company && <p className="text-xs text-destructive">{errors.company.message}</p>}
        </div>

        <div className="space-y-2">
          <label className="text-sm font-medium text-foreground">How can we help?</label>
          <Textarea 
            {...register("message")} 
            placeholder="Tell us about your agent infrastructure and governance needs..."
            className="bg-background/50 border-border min-h-[120px] resize-none focus-visible:ring-primary/50"
          />
          {errors.message && <p className="text-xs text-destructive">{errors.message.message}</p>}
        </div>

        <Button 
          type="submit" 
          disabled={isSubmitting}
          className="w-full h-12 text-base font-semibold bg-foreground text-background hover:bg-foreground/90 transition-colors"
        >
          {isSubmitting ? (
            <>
              <Loader2 className="mr-2 h-5 w-5 animate-spin" />
              Sending...
            </>
          ) : (
            "Submit Request"
          )}
        </Button>
      </form>
    </div>
  );

  return (
    <section id={id} className="py-24 border-t border-border/50 relative overflow-hidden">
      {/* Decorative background glow */}
      <div className={`absolute top-1/2 -translate-y-1/2 w-[500px] h-[500px] bg-primary/5 rounded-full blur-[100px] pointer-events-none ${alignment === 'left' ? '-right-[200px]' : '-left-[200px]'}`} />
      
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-16 lg:gap-24 items-center">
          {alignment === 'left' ? (
            <>
              <ContentBlock />
              <FormBlock />
            </>
          ) : (
            <>
              <div className="order-2 lg:order-1">
                <FormBlock />
              </div>
              <div className="order-1 lg:order-2">
                <ContentBlock />
              </div>
            </>
          )}
        </div>
      </div>
    </section>
  );
}
