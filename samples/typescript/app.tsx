interface Props {
  name: string;
}

export const Greeting = ({ name }: Props) => <div>Hello {name}</div>;
